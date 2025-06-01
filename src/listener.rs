use crate::messages::StateMessage;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::{io, thread};
use std::time::SystemTime;

pub struct PacketListener {
    interface: NetworkInterface,
    ui_callback_tx: Sender<StateMessage>,
}

impl PacketListener {

    pub fn start(interface_index: u32, ui_callback_tx: Sender<StateMessage>) -> io::Result<JoinHandle<io::Result<()>>> {

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
        
        let mut packet_listener = PacketListener { interface, ui_callback_tx };
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

        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
        
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.ui_callback_tx.send(StateMessage::PacketReceived(timestamp, eth_packet.payload().to_vec())).unwrap();
            }
            EtherTypes::Vlan => {
                // unwrap VLAN packets
                let vlan = VlanPacket::new(eth_packet.payload()).unwrap();
                if vlan.get_ethertype() == EtherTypes::Ipv4 {
                    self.ui_callback_tx.send(StateMessage::PacketReceived(timestamp, vlan.payload().to_vec())).unwrap();
                }
            }
            _ => {
                // ignore
            }
        }
    }

}

fn find_interface(interface_index: u32) -> io::Result<NetworkInterface> {
    datalink::interfaces().into_iter()
        .find(|i| i.index == interface_index)
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Could not find interface by index: {}", interface_index).as_str()))
}

