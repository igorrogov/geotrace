use std::net::Ipv4Addr;

pub enum StateMessage {
    // ICMP packet was sent: number and time sent
    PacketSent(u16, u128),
    // ICMP packet received with timestamp and payload
    PacketReceived(u128, Vec<u8>),
    // to Sender: packet sequence number where the destination was reached
    DestinationReached(u16),
    ResolveRequest(u16, Ipv4Addr),
    // IP address has been resolved: index, address
    AddressResolved(u16, String),
}

pub struct ParsedPacket {
    pub index: u16,
    pub icmp_identifier: u16,
    pub address: Ipv4Addr,
}