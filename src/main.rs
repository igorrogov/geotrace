mod sender;
mod messages;
mod listener;

use crate::listener::PacketListener;
use crate::messages::{StateMessage, PacketSentMessage, PacketReceivedMessage};
use crate::sender::PacketSender;
use clap::{arg, Parser};
use crossterm::{cursor, terminal, ExecutableCommand};
use pnet::datalink;
use std::sync::mpsc;
use std::{io, process};
use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use crossterm::style::Print;
use dns_lookup::lookup_addr;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// List all interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// IP address to traceroute
    #[arg(required_unless_present = "list")]
    address: Option<String>,

    /// Index of the network interface to use (use --list to list of interfaces)
    #[arg(short, long)]
    #[arg(required_unless_present = "list")]
    interface: Option<u32>,
    
    /// Resolve IP addresses to hostnames. Default: false.
    #[arg(short, long)]
    resolve: bool
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.list {
        list_interfaces_and_exit();
    }

    io::stdout().execute(terminal::Clear(terminal::ClearType::All))?;

    let target = args.address.expect("missing address").parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let interface_index = args.interface.expect("missing interface");

    let (state_ch_tx, state_ch_rx) = mpsc::channel::<StateMessage>();
    let (timestamps_ch_tx, timestamps_ch_rx) = mpsc::channel::<PacketSentMessage>();
    let (ui_callback_tx, ui_callback_rx) = mpsc::channel::<PacketReceivedMessage>();

    PacketListener::start(interface_index, ui_callback_tx)?;
    PacketSender::start(target, state_ch_rx, timestamps_ch_tx)?;

    let mut timestamps = HashMap::<u8, u128>::new();
    
    // UI loop
    while let Ok(msg) = ui_callback_rx.recv() {

        // read new timestamps
        read_new_timestamps(&timestamps_ch_rx, &mut timestamps);
        
        let host = if args.resolve {
            lookup_addr(&msg.source_address.into()).unwrap_or_else(|_| "[Unknown]".to_string())
        } else {
            String::from("")
        };

        if msg.source_address == target {
            // final IP reached -> notify the main thread
            state_ch_tx.send(StateMessage::DestinationReached(msg.seq_number as u16)).expect("failed to send DestinationReached");
        }

        let sent_time = match timestamps.get(&msg.seq_number) {
            Some(t) => *t,
            None => 0u128,
        };

        let mut ping = 0u128;
        if sent_time > 0 {
            ping = msg.timestamp - sent_time;
        }
        
        io::stdout().execute(cursor::MoveTo(0, (msg.seq_number + 1) as u16)).expect("move cursor");
        io::stdout().execute(terminal::Clear(terminal::ClearType::CurrentLine)).expect("failed to clear line");

        io::stdout().execute(Print(format!(
            "{:2}. {:16} - code: {:2}, type: {:2}, time: {:5}ms, host: {:3}",
            msg.seq_number,
            msg.source_address,
            msg.icmp_code.0,
            msg.icmp_type.0,
            ping,
            host
        ))).expect("failed to print");
    }
    
    Ok(())
}

fn read_new_timestamps(rx: &Receiver<PacketSentMessage>, timestamps: &mut HashMap<u8, u128>) {
    loop {
        match rx.try_recv() {
            Ok(PacketSentMessage { index, timestamp }) => {
                timestamps.insert(index, timestamp);
            },
            Err(_) => break, // no more packets for now, exit
        }
    }
}

fn list_interfaces_and_exit() {
    let mut interfaces = datalink::interfaces();
    interfaces.sort_by_key(|k| k.index);
    interfaces.iter().for_each(|i| {
        let ips = i.ips.iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.ip())
            .filter(|ip| !ip.is_unspecified())
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>();

        if !ips.is_empty() {
            println!("Index: {:2}, IP: {}, Description: {}", i.index, ips.join(", "), i.description);
        }
    });

    process::exit(0);
}


