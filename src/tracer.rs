use crate::messages::{Message, PacketSentMessage};

use crate::sender::PacketSender;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::io;
use crate::listener::PacketListener;

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
        
        let listener_handle = PacketListener::start(self.interface_index, self.target, self.resolve, ch_tx, pch_rx)?;
        let sender_handle = PacketSender::start(self.target, ch_rx, pch_tx)?;
        
        listener_handle.join().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "listener"))??;
        sender_handle.join().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "sender"))??;
        
        Ok(())
    }
    
    
    
}