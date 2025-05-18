use crate::build_echo_request;
use crossterm::style::Print;
use crossterm::{cursor, terminal, ExecutableCommand};
use datalink::NetworkInterface;
use dns_lookup::lookup_addr;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkReceiver;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes::EchoReply;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportSender};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;
use std::time::{Duration, SystemTime};
use std::{io, thread};
use std::thread::JoinHandle;

pub struct Tracer {

    interface_index: u32,
    target: Ipv4Addr,
    resolve: bool,
    // callback: Sender<Message>,
}

impl Tracer {

    pub fn new(interface_index: u32, target_str: String, resolve: bool) -> io::Result<Tracer> {
        let target = target_str.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Tracer { interface_index, target, resolve })
    }
    
    pub fn start(&self) -> io::Result<()> {
        // channel for communication between sender and receiver threads
        let (ch_tx, ch_rx) = mpsc::channel::<Message>();
        let (pch_tx, pch_rx) = mpsc::channel::<PacketSentMessage>();
        
        let listener_handle = self.start_listener(ch_tx, pch_rx)?;
        let sender_handle = self.start_sender(ch_rx, pch_tx)?;
        
        listener_handle.join().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "listener"))??;
        sender_handle.join().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "sender"))??;
        
        Ok(())
    }
    
    fn start_listener(&self, ch_tx: Sender<Message>, pch_rx: Receiver<PacketSentMessage>,) -> io::Result<JoinHandle<io::Result<()>>> {
        
        let interface = find_interface(self.interface_index)?;
        io::stdout().execute(cursor::MoveTo(0, 0))?;
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
            Ok(_) => return Err(io::Error::new(io::ErrorKind::Other, "unhandled channel type")),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("unable to create channel: {}", e))),
        };
        
        let timestamps = HashMap::<u8, u128>::new();
        let mut packet_listener = PacketListener { target: self.target, resolve: self.resolve, interface, ch_tx, pch_rx, timestamps };
        Ok(thread::spawn(move || { packet_listener.run(eth_rx) }))
    }

    fn start_sender(&self, ch_rx: Receiver<Message>, pch_tx: Sender<PacketSentMessage>) -> io::Result<JoinHandle<io::Result<()>>> {
        let (transport_sender, _) = transport_channel(1024, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))?;
        let mut packet_sender = PacketSender { transport_sender, target: self.target, pch_tx, ch_rx };
        Ok(thread::spawn(move || { packet_sender.run() }))
    }
    
}

struct PacketListener {
    target: Ipv4Addr,
    resolve: bool,
    interface: NetworkInterface,
    ch_tx: Sender<Message>,
    pch_rx: Receiver<PacketSentMessage>,
    timestamps: HashMap<u8, u128>,
}

impl PacketListener {
    
    fn run(&mut self, mut eth_rx: Box<dyn DataLinkReceiver>) -> io::Result<()> {
        // println!("Listening for ICMP packets...");
        self.ch_tx.send(Message::ListeningThreadReady).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        loop {
            match eth_rx.next() {
                Ok(packet_data) => self.handle_packet(packet_data),
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }

    fn handle_packet(&mut self, packet_data: &[u8]) {
        let eth_packet = EthernetPacket::new(packet_data).unwrap();

        // TODO: implement better filtering
        if self.interface.mac.unwrap() == eth_packet.get_source() {
            // outgoing packet
            return;
        }

        // TODO: implement async handling of packets

        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.handle_ipv4_payload(eth_packet.payload());
            }
            EtherTypes::Vlan => {
                // unwrap VLAN packets
                let vlan = VlanPacket::new(eth_packet.payload()).unwrap();
                if vlan.get_ethertype() == EtherTypes::Ipv4 {
                    self.handle_ipv4_payload(vlan.payload());
                }
            }
            _ => {
                // ignore
            }
        }
    }

    fn handle_ipv4_payload(&mut self, payload: &[u8]) {
        let ipv4 = Ipv4Packet::new(payload).unwrap();
        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
            let icmp_packet = IcmpPacket::new(ipv4.payload()).expect("Icmp packet");
            let host = if self.resolve {
                lookup_addr(&ipv4.get_source().into()).unwrap_or_else(|_| "[Unknown]".to_string())
            } else {
                String::from("")
            };

            let seq_number = get_seq_number(&icmp_packet, ipv4.payload()) as u8;

            // io::stdout().execute(cursor::MoveTo(0, 1)).expect("move cursor");
            // io::stdout().execute(Print(format!("Received packet: {}", seq_number))).unwrap();

            io::stdout().execute(cursor::MoveTo(0, (seq_number + 1) as u16)).expect("move cursor");
            io::stdout().execute(terminal::Clear(terminal::ClearType::CurrentLine)).expect("failed to clear line");

            self.read_new_timestamps();
            
            let sent_time = match self.timestamps.get(&seq_number) {
                Some(t) => *t,
                None => 0u128,
            };
            
            let mut ping = 0u128;
            if sent_time > 0 {
                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
                ping = now - sent_time;
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

            if ipv4.get_source() == self.target {
                // final IP reached -> notify the main thread
                self.ch_tx.send(Message::DestinationReached(seq_number as u16)).expect("failed to send DestinationReached");
            }
        }
    }
    
    fn read_new_timestamps(&mut self) {
        loop {
            match self.pch_rx.try_recv() {
                Ok(PacketSentMessage { index, timestamp }) => {
                    self.timestamps.insert(index, timestamp);
                },
                Err(_) => break, // no more packets for now, exit
            }
        }
    }
    
}

struct PacketSender {
    target: Ipv4Addr,
    transport_sender: TransportSender,
    pch_tx: Sender<PacketSentMessage>,
    ch_rx: Receiver<Message>,
}

impl PacketSender {
    
    fn run(&mut self) -> io::Result<()> {

        // wait until the listening thread is started and ready to receive packets
        self.ch_rx.recv().map_err(|_| io::Error::new(io::ErrorKind::Other, "error waiting for packet listener"))?;

        let mut attempt: u8 = 0;
        let mut max_hops: u8 = 32;
        loop {
            attempt += 1;
            let mut icmp_buf: Vec<u8> = vec![0; EchoRequestPacket::minimum_packet_size()];
            build_echo_request(&mut icmp_buf, attempt);
            self.transport_sender.set_ttl(attempt)?;
            
            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
            self.pch_tx.send(PacketSentMessage { index: attempt, timestamp }).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            self.transport_sender.send_to(IcmpPacket::new(&icmp_buf[..]).unwrap(), IpAddr::V4(self.target))?;

            match self.ch_rx.recv_timeout(Duration::from_millis(500)) {
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
    
}

fn find_interface(interface_index: u32) -> io::Result<NetworkInterface> {
    datalink::interfaces().into_iter()
        .find(|i| i.index == interface_index)
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Could not find interface by index: {}", interface_index).as_str()))
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

pub enum Message {
    ListeningThreadReady,
    DestinationReached(u16),
}

struct PacketSentMessage {
    index: u8,
    timestamp: u128,
}