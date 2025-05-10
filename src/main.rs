use clap::{arg, Parser};
use crossterm::{cursor, terminal, ExecutableCommand};
use dns_lookup::lookup_addr;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkReceiver;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes::EchoReply;
use pnet::packet::icmp::{checksum, IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{mpsc, Arc, Mutex};
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};
use std::{io, process, thread};
use std::collections::HashMap;
use crossterm::style::Print;
use pnet::packet::vlan::VlanPacket;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// List all interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// IP address to traceroute
    #[arg(required_unless_present = "list")]
    address: Option<String>,

    /// Index of the network interface to use (use --list to list of interfaces)
    #[arg(short, long)]
    #[arg(required_unless_present = "list")]
    interface: Option<u32>,
    
    /// Resolve IP addresses to hostnames. Default: false.
    #[arg(short, long)]
    resolve: bool
}

enum Message {
    ListeningThreadReady,
    DestinationReached(u16)
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.list {
        list_interfaces_and_exit();
    }

    let mut stdout = io::stdout();

    stdout.execute(terminal::Clear(terminal::ClearType::All))?;

    let target_address_string = args.address.expect("Address must be specified");
    let target_address = target_address_string.parse()
        .expect(format!("Invalid address: {}", target_address_string).as_str());

    let interface_index = args.interface.expect("Interface must be specified");
    let interface = datalink::interfaces().into_iter()
        .find(|i| i.index == interface_index)
        .expect(format!("Could not find interface by index: {}", interface_index).as_str());

    stdout.execute(cursor::MoveTo(0, 0))?;

    println!("Using interface: {} ({}, index: {})",
             interface.description,
             interface.ips.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(", "),
             interface.index
    );

    let (_, eth_rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    let (ch_tx, ch_rx) = mpsc::channel::<Message>();

    // attempt -> ping time (ms)
    let map = Arc::new(Mutex::new(HashMap::<u8, u128>::new()));

    let resolve = args.resolve;
    listen_icmp(map.clone(), interface.mac.unwrap(), target_address, eth_rx, ch_tx, resolve);

    // wait until the listening thread is started and ready to receive packets
    ch_rx.recv().expect("unable to receive message");

    let (mut sender, _) = transport_channel(1024, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
        .expect("transport_channel");

    let mut attempt: u8 = 0;
    let mut max_hops: u8 = 32;
    loop {

        attempt += 1;
        let mut icmp_buf: Vec<u8> = vec![0; EchoRequestPacket::minimum_packet_size()];
        build_echo_request(&mut icmp_buf, attempt);
        sender.set_ttl(attempt).expect("failed to set ttl");

        {
            let mut map_guard = map.lock().unwrap();
            let sent_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
            map_guard.insert(attempt, sent_time);
            // stdout.execute(Print(format!("Sending request: {:2} ({})", attempt, sent_time)))?;
        }

        sender.send_to(IcmpPacket::new(&icmp_buf[..]).unwrap(), IpAddr::V4(target_address))?;

        match ch_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Message::DestinationReached(hops)) => {
                max_hops = hops as u8;
            },
            _ => {}
        };

        // thread::sleep(Duration::from_millis(500));

        // limit the max number of hops (either the limit or the real number of hops)
        if attempt >= max_hops {
            attempt = 0;
        }
    }
}

fn list_interfaces_and_exit() {
    let mut interfaces = datalink::interfaces();
    interfaces.sort_by_key(|k| k.index);
    interfaces.iter().for_each(|i| {
        let ips = i.ips.iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.ip())
            .filter(|ip| !ip.is_unspecified())
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>();

        if !ips.is_empty() {
            println!("Index: {:2}, IP: {}, Description: {}", i.index, ips.join(", "), i.description);
        }
    });

    process::exit(0);
}

fn build_echo_request(buf: &mut [u8], attempt: u8) {
    let mut echo_packet = MutableEchoRequestPacket::new(buf).unwrap();

    echo_packet.set_sequence_number(attempt as u16);
    echo_packet.set_identifier(0x123);
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_icmp_code(IcmpCode::new(0));

    let echo_checksum = checksum(&IcmpPacket::new(echo_packet.packet()).unwrap());
    echo_packet.set_checksum(echo_checksum);
}

fn listen_icmp(map: Arc<Mutex<HashMap<u8, u128>>>, iface_mac: MacAddr, target_ip: Ipv4Addr, mut eth_rx: Box<dyn DataLinkReceiver>, ch_tx: Sender<Message>, resolve: bool) -> JoinHandle<()> {
    thread::spawn(move || {
        // println!("Listening for ICMP packets...");
        ch_tx.send(Message::ListeningThreadReady).expect("failed to send ListeningThreadReady");
        loop {
            match eth_rx.next() {
                Ok(packet_data) => {
                    if handle_packet(&map, &ch_tx, iface_mac, target_ip, packet_data, resolve) {
                        return;
                    }
                }
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    })
}

fn handle_packet(map: &Arc<Mutex<HashMap<u8, u128>>>, ch_tx: &Sender<Message>, iface_mac: MacAddr, target_ip: Ipv4Addr, packet_data: &[u8], resolve: bool) -> bool {
    let eth_packet = EthernetPacket::new(packet_data).unwrap();

    // TODO: implement better filtering
    if iface_mac == eth_packet.get_source() {
        // outgoing packet
        return false;
    }

    // TODO: implement async handling of packets

    match eth_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let payload = eth_packet.payload();
            handle_ipv4_payload(map, ch_tx, target_ip, resolve, payload);
        }
        EtherTypes::Vlan => {
            // unwrap VLAN packets
            let vlan = VlanPacket::new(eth_packet.payload()).unwrap();
            if vlan.get_ethertype() == EtherTypes::Ipv4 {
                handle_ipv4_payload(map, ch_tx, target_ip, resolve, vlan.payload());
            }
        }
        _ => {
            // ignore
        }
    }
    false
}

fn handle_ipv4_payload(map: &Arc<Mutex<HashMap<u8, u128>>>, ch_tx: &Sender<Message>, target_ip: Ipv4Addr, resolve: bool, payload: &[u8]) {
    let ipv4 = Ipv4Packet::new(payload).unwrap();
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        let icmp_packet = IcmpPacket::new(ipv4.payload()).expect("Icmp packet");
        let host = if resolve {
            lookup_addr(&ipv4.get_source().into()).unwrap_or_else(|_| "[Unknown]".to_string())
        } else {
            String::from("")
        };

        let seq_number = get_seq_number(&icmp_packet, ipv4.payload()) as u8;

        // io::stdout().execute(cursor::MoveTo(0, 1)).expect("move cursor");
        // io::stdout().execute(Print(format!("Received packet: {}", seq_number))).unwrap();

        io::stdout().execute(cursor::MoveTo(0, (seq_number + 3) as u16)).expect("move cursor");
        io::stdout().execute(terminal::Clear(terminal::ClearType::CurrentLine)).expect("failed to clear line");

        let sent: u128;
        {
            let map_guard = map.lock().unwrap();
            sent = match map_guard.get(&seq_number) {
                Some(t) => *t,
                None => 0u128,
            }
        }

        let mut ping = 0u128;
        if sent > 0 {
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
            ping = now - sent;
        }

        io::stdout().execute(Print(format!(
            "{:2}. {:16} - code: {:2}, type: {:2}, time: {:5}ms, host: {:3}",
            seq_number,
            ipv4.get_source(),
            icmp_packet.get_icmp_code().0,
            icmp_packet.get_icmp_type().0,
            ping,
            host
        ))).expect("failed to print");

        if ipv4.get_source() == target_ip {
            // final IP reached -> notify the main thread
            ch_tx.send(Message::DestinationReached(seq_number as u16)).expect("failed to send DestinationReached");
            // return true;
        }
    }
}

fn get_seq_number(icmp_packet: &IcmpPacket, ip_packet_data: &[u8]) -> u32 {
    let icmp_payload = icmp_packet.payload();
    if icmp_payload.len() < Ipv4Packet::minimum_packet_size() + IcmpPacket::minimum_packet_size() {
        // no payload, return the original sequence number
        if icmp_packet.get_icmp_type() == EchoReply {
            return EchoReplyPacket::new(ip_packet_data).unwrap().get_sequence_number() as u32
        }
        return 0
    }

    // Parse ICMP payload as original IPv4 packet

    let original_icmp = IcmpPacket::new(&icmp_payload[Ipv4Packet::minimum_packet_size()..])
        .expect("Original ICMP Packet");
    let original_echo_request =
        EchoRequestPacket::new(original_icmp.payload()).expect("Original Echo Request");
    original_echo_request.get_sequence_number() as u32
}
