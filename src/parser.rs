use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes::EchoReply;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use crate::messages::{ParsedPacket};

pub fn parse(payload: &[u8]) -> Option<ParsedPacket> {
    let ipv4 = Ipv4Packet::new(payload).unwrap();
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        let icmp_packet = IcmpPacket::new(ipv4.payload()).expect("Icmp packet");
        let (seq_number, id) = get_icmp_attrs(&icmp_packet, ipv4.payload());
        Some(ParsedPacket { index: seq_number, icmp_identifier: id, address: ipv4.get_source() })
    }
    else {
        None
    }
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