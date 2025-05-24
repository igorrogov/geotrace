use std::net::Ipv4Addr;
use pnet::packet::icmp::{IcmpCode, IcmpType};

pub enum StateMessage {
    ListeningThreadReady,
    DestinationReached(u16),
}

pub struct PacketSentMessage {
    pub index: u8,
    pub timestamp: u128,
}

pub struct PacketReceivedMessage {
    pub timestamp: u128,
    pub seq_number: u8,
    pub source_address: Ipv4Addr,
    pub icmp_code: IcmpCode,
    pub icmp_type: IcmpType,
}