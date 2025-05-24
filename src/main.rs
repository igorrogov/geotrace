mod tracer;
mod sender;
mod messages;
mod listener;

use crate::tracer::Tracer;

use clap::{arg, Parser};
use crossterm::{cursor, terminal, ExecutableCommand};
use pnet::datalink;
use std::{io, process};

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

    let mut stdout = io::stdout();

    stdout.execute(terminal::Clear(terminal::ClearType::All))?;

    let tracer = Tracer::new(
        // ch_tx,
        args.interface.expect("missing interface"), 
        args.address.expect("missing address"),
        args.resolve
    )?;
    
    tracer.start()?;
    
    stdout.execute(cursor::MoveTo(0, 0))?;

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


