use std::{io, thread};
use std::sync::mpsc::{Receiver, Sender};
use whois_rust::{WhoIs, WhoIsLookupOptions};
use crate::messages::StateMessage;

pub fn start(rx: Receiver<StateMessage>, ui_callback_tx: Sender<StateMessage>) -> io::Result<()> {
    thread::spawn(move || {
        // TODO: configure Whois server
        let whois = WhoIs::from_host("whois.arin.net").expect("failed to load whois");
        
        while let Ok(msg) =  rx.recv() {
            match msg {
                StateMessage::WhoiseResolveRequest(index, address) => {
                    let result = whois.lookup(WhoIsLookupOptions::from_string(address.to_string()).unwrap()).unwrap();
                    let net_name = extract_net_name(result).unwrap_or("".to_string());
                    ui_callback_tx.send(StateMessage::WhoiseResolveResponse(index, net_name))
                        .expect("failed to send AddressResolved");
                },
                _ => {}
            }
        }
    });
    Ok(())
}

fn extract_net_name(result: String) -> Option<String> {
    for line in result.lines() {
        if line.starts_with("#") {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            // println!("{}: {}", key, value);
            if key.eq_ignore_ascii_case("NetName") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}