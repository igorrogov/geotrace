use crate::messages::{StateMessage};

use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::{checksum, IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportSender};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};
use std::{io, thread};

pub struct PacketSender {
    target: Ipv4Addr,
    icmp_identifier: u16,
    transport_sender: TransportSender,
    ui_callback_tx: Sender<StateMessage>,
    sender_callback_rx: Receiver<StateMessage>
}

impl PacketSender {

    pub fn start(target: Ipv4Addr, icmp_identifier: u16, sender_callback_rx: Receiver<StateMessage>, ui_callback_tx: Sender<StateMessage>, max_hops_initial: u8) -> io::Result<JoinHandle<io::Result<()>>> {
        let (transport_sender, _) = transport_channel(1024, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))?;
        let mut packet_sender = PacketSender { target, icmp_identifier, transport_sender, ui_callback_tx, sender_callback_rx };
        Ok(thread::spawn(move || { packet_sender.run(max_hops_initial) }))
    }
    
    fn run(&mut self, max_hops_initial: u8) -> io::Result<()> {

        // wait until the listening thread is started and ready to receive packets
        // self.state_ch_rx.recv().map_err(|_| io::Error::new(io::ErrorKind::Other, "error waiting for packet listener"))?;

        let mut attempt: u8 = 0;
        let mut max_hops: u8 = max_hops_initial;
        loop {
            attempt += 1;
            let mut icmp_buf: Vec<u8> = vec![0; EchoRequestPacket::minimum_packet_size()];
            Self::build_echo_request(&mut icmp_buf, attempt, self.icmp_identifier);
            self.transport_sender.set_ttl(attempt)?;

            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
            self.ui_callback_tx.send(StateMessage::PacketSent(attempt as u16, timestamp)).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            self.transport_sender.send_to(IcmpPacket::new(&icmp_buf[..]).unwrap(), IpAddr::V4(self.target))?;

            match self.sender_callback_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(StateMessage::DestinationReached(hops)) => {
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

    fn build_echo_request(buf: &mut [u8], attempt: u8, icmp_identifier: u16) {
        let mut echo_packet = MutableEchoRequestPacket::new(buf).unwrap();

        echo_packet.set_sequence_number(attempt as u16);
        echo_packet.set_identifier(icmp_identifier);
        echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_packet.set_icmp_code(IcmpCode::new(0));

        let echo_checksum = checksum(&IcmpPacket::new(echo_packet.packet()).unwrap());
        echo_packet.set_checksum(echo_checksum);
    }

}