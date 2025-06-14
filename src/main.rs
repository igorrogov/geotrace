mod sender;
mod messages;
mod listener;
mod parser;
mod dns_resolver;
mod whois_resolver;

use crate::listener::PacketListener;
use crate::messages::StateMessage;
use crate::sender::PacketSender;
use clap::{arg, Parser};
use crossterm::style::{Attribute, Print, PrintStyledContent, Stylize};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute, terminal};
use io::{Error, ErrorKind};
use pnet::datalink;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::{io, process};
use Attribute::Bold;

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

#[derive(Debug, Clone)]
struct Entry {

    index: u16,
    address: Option<Ipv4Addr>,
    hostname: Option<String>,
    netname: Option<String>,
    last_sent_time: u128,
    last_ping: u128,

    dns_request_sent: bool,
    whois_request_sent: bool,
}

impl Entry {
    
    fn new(index: u16) -> Entry {
        Entry {index, address: None, hostname: None, netname: None, last_sent_time: 0, last_ping: 0, dns_request_sent: false, whois_request_sent: false}
    }
    
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.list {
        list_interfaces_and_exit();
    }

    const MAX_HOPS: usize = 32;
    
    // generate random IDs to distinguish between our and other ICMP replies
    let mut rng = rand::rng();
    let icmp_identifier: u16 = rng.random();

    let mut stdout = io::stdout();

    ctrlc::set_handler(move || {
        execute!(io::stdout(),
            cursor::Show,
            LeaveAlternateScreen)
            .expect("Error leaving alternate screen");
        process::exit(0);
    }).map_err(|e| Error::new(ErrorKind::Interrupted, e))?;

    let target = parse_or_resolve_address(args.address)?;
    let interface_index = args.interface.expect("missing interface");

    execute!(stdout,
        EnterAlternateScreen,
        cursor::Hide,
        terminal::Clear(terminal::ClearType::All),
        cursor::MoveTo(0, 0),
        Print(format!("Target address:  {}", target)),
        cursor::MoveTo(0, 3),
        PrintStyledContent(format!("{:>4}   {:<18}{:>10}   {:<50}{:<25}", "Hop", "IP Address", "Ping", "Hostname", "Netname").attribute(Bold)),
    )?;

    let (ui_callback_tx, ui_callback_rx) = mpsc::channel::<StateMessage>();
    let (sender_callback_tx, sender_callback_rx) = mpsc::channel::<StateMessage>();
    let (dns_callback_tx, dns_callback_rx) = mpsc::channel::<StateMessage>();
    let (whois_callback_tx, whois_callback_rx) = mpsc::channel::<StateMessage>();
    
    PacketListener::start(interface_index, ui_callback_tx.clone())?;
    PacketSender::start(target, icmp_identifier, sender_callback_rx, ui_callback_tx.clone(), MAX_HOPS as u8)?;
    dns_resolver::start(dns_callback_rx, ui_callback_tx.clone())?;
    whois_resolver::start(whois_callback_rx, ui_callback_tx)?;

    let mut entries: [Entry; MAX_HOPS+1] = std::array::from_fn(|i| Entry::new(i as u16));
    let mut destination_index: Option<u16> = None;
    let mut max_entry_displayed = 0u16;
    
    // UI loop
    while let Ok(msg) = ui_callback_rx.recv() {

        match msg {
            StateMessage::PacketSent(index, sent_time) => {
                if index > MAX_HOPS as u16 {
                    continue;
                }
                if destination_index.is_some() && index > destination_index.unwrap() {
                    continue;
                }
                
                let entry = &mut entries[index as usize];
                entry.last_sent_time = sent_time;
                draw_entry(&entry, &mut max_entry_displayed)?;
            },
            StateMessage::PacketReceived(timestamp, payload) => {
                match parser::parse(&payload) {
                    None => {}
                    Some(packet) => {
                        if packet.icmp_identifier != icmp_identifier {
                            // ICMP reply from a different app / source, ignore
                            continue;
                        }
                        if packet.index > MAX_HOPS as u16 {
                            continue;
                        }
                        if destination_index.is_some() && packet.index > destination_index.unwrap() {
                            continue;
                        }
                        
                        let entry = &mut entries[packet.index as usize];
                        entry.address = Some(packet.address);
                        entry.last_ping = timestamp - entry.last_sent_time;

                        if args.resolve && entry.hostname.is_none() && !entry.dns_request_sent {
                            // resolve IP address async
                            dns_callback_tx.send(StateMessage::DnsResolveRequest(packet.index, packet.address))
                                .expect("failed to send ResolveRequest");
                            entry.dns_request_sent = true;
                        }
                        if args.resolve && entry.netname.is_none() && !entry.whois_request_sent {
                            // resolve nem name via Whois async
                            whois_callback_tx.send(StateMessage::WhoiseResolveRequest(packet.index, packet.address))
                                .expect("failed to send WhoiseResolveRequest");
                            entry.whois_request_sent = true;
                        }

                        draw_entry(&entry, &mut max_entry_displayed)?;

                        // notify about destination reached
                        if destination_index.is_none() && packet.address == target {
                            destination_index = Some(packet.index);
                            // final IP reached -> notify the main thread
                            sender_callback_tx.send(StateMessage::DestinationReached(packet.index))
                                .expect("failed to send DestinationReached");
                            
                            // clear all entries beyond destination
                            if max_entry_displayed > packet.index {
                                for row in (packet.index + 1)..(max_entry_displayed + 1) {
                                    execute!(io::stdout(),  
                                        cursor::MoveTo(0, row + 3),
                                        terminal::Clear(terminal::ClearType::CurrentLine)
                                    )?;
                                }
                            }
                        }
                    }
                }
            },
            StateMessage::DnsResolveResponse(index, hostname) => {
                if destination_index.is_some() && index > destination_index.unwrap() {
                    continue;
                }
                let entry = &mut entries[index as usize];
                entry.hostname = Some(hostname);
                draw_entry(&entry, &mut max_entry_displayed)?;
            },
            StateMessage::WhoiseResolveResponse(index, netname) => {
                if destination_index.is_some() && index > destination_index.unwrap() {
                    continue;
                }
                let entry = &mut entries[index as usize];
                entry.netname = Some(netname);
                draw_entry(&entry, &mut max_entry_displayed)?;
            },
            _ => {}
        }
    }
    
    Ok(())
}

fn draw_entry(entry: &Entry, max_entry_displayed: &mut u16) -> io::Result<()> {
    let hostname = match entry.hostname.as_deref() {
        Some(hostname) => hostname,
        None => if entry.dns_request_sent { "Resolving..." } else { "" },
    };
    let netname = match entry.netname.as_deref() {
        Some(netname) => netname,
        None => if entry.whois_request_sent { "Resolving..." } else { "" },
    };
    let address = match entry.address {
        Some(address) => address.to_string(),
        None => "Waiting...".to_string(),
    };
    execute!(io::stdout(),
        cursor::MoveTo(0, entry.index + 3),
        terminal::Clear(terminal::ClearType::CurrentLine),
        Print(format!("{:3}.   {:18}{:>8}ms   {:<50}{:<25}", entry.index, address, entry.last_ping, hostname, netname))
    )?;

    if entry.index > *max_entry_displayed {
        *max_entry_displayed = entry.index;
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
