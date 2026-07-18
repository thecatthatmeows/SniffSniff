mod ethertypes;
mod parser;
mod ports;
mod cli;

use std::collections::HashMap;
use sysinfo::{System, Pid};
use clap::Parser;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use pcap::Capture;
use crate::{cli::Args, parser::DisplayPacketOptions};
use tokio::sync::RwLock;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref PORT_TO_PIDS: RwLock<HashMap<u16, Vec<u32>>> = RwLock::new(HashMap::new());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let af_flags = AddressFamilyFlags::all();
    let proto_flags = ProtocolFlags::all();
    let sockets_info = get_sockets_info(af_flags, proto_flags).expect("Couldn't get sockets info");

    // set every processes sockets ports first
    let mut port_to_pids: HashMap<u16, Vec<u32>> = HashMap::new();
    for si in &sockets_info {
        let port = match &si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => tcp.local_port,
            ProtocolSocketInfo::Udp(udp) => udp.local_port,
        };
        port_to_pids.entry(port).or_default()
            .extend(si.associated_pids.iter().copied());
    }
    {
        let mut w = PORT_TO_PIDS.write().await;
        *w = port_to_pids;
    }

    println!("Capturing");
    let mut cap = Capture::from_device("wlp0s20f3").unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .unwrap();

    let link_type = cap.get_datalink();
    println!("Link type: {}", link_type.get_name().unwrap_or("Unknown".to_string()));

    let mut packet_count = 0;
    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        let data = packet.data;

        if let Some(parsed) = parser::parse_tcp_ipv4(data) {
            println!("=== Packet {} ===", packet_count);
            let options = DisplayPacketOptions {
                show_payload: args.show_payload,
                filter_by_pid: args.pid
            };
            parsed.print(Some(options)).await;
        }
    }

    Ok(())
}
