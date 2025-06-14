use std::{io, thread};
use std::sync::mpsc::{Receiver, Sender};
use crate::messages::StateMessage;

pub fn start(rx: Receiver<StateMessage>, ui_callback_tx: Sender<StateMessage>) -> io::Result<()> {
    thread::spawn(move || {
        while let Ok(msg) =  rx.recv() {
            match msg {
                StateMessage::DnsResolveRequest(index, address) => {
                    let hostname = dns_lookup::lookup_addr(&address.into())
                        .unwrap_or_else(|_| "".to_string());
                    ui_callback_tx.send(StateMessage::DnsResolveResponse(index, hostname))
                        .expect("failed to send AddressResolved");
                },
                _ => {}
            }
        }
    });
    Ok(())
}