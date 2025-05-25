mod sender;
mod messages;
mod listener;

use io::{Error, ErrorKind};
use crate::listener::PacketListener;
use crate::messages::{PacketReceivedMessage, PacketSentMessage, StateMessage};
use crate::sender::PacketSender;
use clap::{arg, Parser};
use crossterm::style::Print;
use crossterm::{cursor, queue, terminal};
use pnet::datalink;
use rand::Rng;
use std::collections::HashMap;
use std::io::Write;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::{io, process};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// List all interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// IP address or hostname to traceroute
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

    // generate random IDs to distinguish between our and other ICMP replies
    let mut rng = rand::rng();
    let icmp_identifier: u16 = rng.random();

    let mut stdout = io::stdout();

    queue!(stdout,
        cursor::Hide,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::All)
    )?;
    stdout.flush()?;

    let target = parse_or_resolve_address(args.address)?;
    let interface_index = args.interface.expect("missing interface");

    let (state_ch_tx, state_ch_rx) = mpsc::channel::<StateMessage>();
    let (timestamps_ch_tx, timestamps_ch_rx) = mpsc::channel::<PacketSentMessage>();
    let (ui_callback_tx, ui_callback_rx) = mpsc::channel::<PacketReceivedMessage>();

    PacketListener::start(icmp_identifier, interface_index, ui_callback_tx)?;
    PacketSender::start(target, icmp_identifier, state_ch_rx, timestamps_ch_tx)?;

    let mut timestamps = HashMap::<u16, u128>::new();
    
    // UI loop
    while let Ok(msg) = ui_callback_rx.recv() {

        // read new timestamps
        read_new_timestamps(&timestamps_ch_rx, &mut timestamps);
        
        let host = if args.resolve {
            dns_lookup::lookup_addr(&msg.source_address.into()).unwrap_or_else(|_| "[Unknown]".to_string())
        } else {
            String::from("")
        };

        if msg.source_address == target {
            // final IP reached -> notify the main thread
            state_ch_tx.send(StateMessage::DestinationReached(msg.seq_number)).expect("failed to send DestinationReached");
        }

        let sent_time = match timestamps.get(&msg.seq_number) {
            Some(t) => *t,
            None => 0u128,
        };

        let mut ping = 0u128;
        if sent_time > 0 {
            ping = msg.timestamp - sent_time;
        }

        queue!(stdout,
            cursor::MoveTo(0, msg.seq_number + 1),
            terminal::Clear(terminal::ClearType::CurrentLine),
            Print(format!("{:2}. {:16} - time: {:5}ms, host: {:3}", msg.seq_number, msg.source_address, ping, host))
        )?;
        stdout.flush()?;
    }
    
    Ok(())
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

fn parse_or_resolve_address(value: Option<String>) -> io::Result<Ipv4Addr> {
    let string_value = value.ok_or(Error::new(ErrorKind::InvalidInput, "Address not specified"))?;
    match string_value.parse::<Ipv4Addr>() {
        Ok(ip) => Ok(ip),
        Err(_) => { 
            // try to resolve the value as a hostname
            let ips = dns_lookup::lookup_host(&string_value)?;
            let first_ip = ips.into_iter()
                .find(|addr| addr.is_ipv4())
                .ok_or(Error::new(ErrorKind::InvalidInput, "Could not resolve an IPv4 address"))?;
            match first_ip {
                IpAddr::V4(ip) => Ok(ip),
                IpAddr::V6(_) => Err(Error::new(ErrorKind::InvalidInput, "Could not resolve an IPv4 address")),
            }
        }
    }
}

fn read_new_timestamps(rx: &Receiver<PacketSentMessage>, timestamps: &mut HashMap<u16, u128>) {
    loop {
        match rx.try_recv() {
            Ok(PacketSentMessage { index, timestamp }) => {
                timestamps.insert(index as u16, timestamp);
            },
            Err(_) => break, // no more packets for now, exit
        }
    }
}
