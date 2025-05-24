use std::net::Ipv4Addr;

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
    pub seq_number: u16,
    pub source_address: Ipv4Addr,
}