use crate::messages::PacketReceivedMessage;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes::EchoReply;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::SystemTime;
use std::{io, thread};

pub struct PacketListener {
    icmp_identifier: u16,
    interface: NetworkInterface,
    ui_callback_tx: Sender<PacketReceivedMessage>,
}

impl PacketListener {

    pub fn start(icmp_identifier: u16, interface_index: u32, ui_callback_tx: Sender<PacketReceivedMessage>) -> io::Result<JoinHandle<io::Result<()>>> {

        let interface = find_interface(interface_index)?;
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
        
        let mut packet_listener = PacketListener { icmp_identifier, interface, ui_callback_tx };
        Ok(thread::spawn(move || { packet_listener.run(eth_rx) }))
    }
    
    fn run(&mut self, mut eth_rx: Box<dyn DataLinkReceiver>) -> io::Result<()> {
        // println!("Listening for ICMP packets...");
        loop {
            match eth_rx.next() {
                Ok(packet_data) => self.handle_packet(packet_data),
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }

    fn handle_packet(&mut self, packet_data: &[u8]) {
        let eth_packet = EthernetPacket::new(packet_data).unwrap();

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
            let (seq_number, id) = get_icmp_attrs(&icmp_packet, ipv4.payload());
            
            if id != self.icmp_identifier {
                // ICMP reply from a different app / source, ignore
                return;
            }
            
            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
            self.ui_callback_tx.send(PacketReceivedMessage { timestamp, seq_number, 
                source_address: ipv4.get_source() })
                .expect("failed to send packet");
        }
    }

}

fn find_interface(interface_index: u32) -> io::Result<NetworkInterface> {
    datalink::interfaces().into_iter()
        .find(|i| i.index == interface_index)
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Could not find interface by index: {}", interface_index).as_str()))
}

fn get_icmp_attrs(icmp_packet: &IcmpPacket, ip_packet_data: &[u8]) -> (u16, u16) {
    let icmp_payload = icmp_packet.payload();
    if icmp_payload.len() < Ipv4Packet::minimum_packet_size() + IcmpPacket::minimum_packet_size() {
        // no payload, return the original sequence number
        if icmp_packet.get_icmp_type() == EchoReply {
            let erp = EchoReplyPacket::new(ip_packet_data).unwrap();
            return (erp.get_sequence_number(), erp.get_identifier())
        }
        return (0, 0)
    }

    // Parse ICMP payload as original IPv4 packet

    let original_icmp = IcmpPacket::new(&icmp_payload[Ipv4Packet::minimum_packet_size()..])
        .expect("Original ICMP Packet");
    let original_echo_request =
        EchoRequestPacket::new(original_icmp.payload()).expect("Original Echo Request");
    (original_echo_request.get_sequence_number(), original_echo_request.get_identifier())
}