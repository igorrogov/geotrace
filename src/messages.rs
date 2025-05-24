pub enum Message {
    ListeningThreadReady,
    DestinationReached(u16),
}

pub struct PacketSentMessage {
    pub index: u8,
    pub timestamp: u128,
}