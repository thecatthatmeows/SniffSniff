mod ethertypes;
mod parser;
mod ports;
mod cli;

use std::collections::HashMap;

use clap::Parser;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use pcap::Capture;
use crate::{cli::Args, parser::DisplayPacketOptions};

fn main() {
    let args = Args::parse();

    let af_flags = AddressFamilyFlags::all();
    let proto_flags = ProtocolFlags::all();
    let sockets_info = get_sockets_info(af_flags, proto_flags).expect("Couldn't get sockets info");

    let mut port_to_pids: HashMap<u16, Vec<u32>> = HashMap::new();
    for si in &sockets_info {
        let port = match &si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => tcp.local_port,
            ProtocolSocketInfo::Udp(udp) => udp.local_port,
        };
        port_to_pids.insert(port, si.associated_pids.clone());
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
        println!("=== Packet {} ===", packet_count);
        let data = packet.data;

        if let Some(parsed) = parser::parse_tcp_ipv4(data) {
            let options = DisplayPacketOptions {
                show_payload: args.show_payload,
            };
            parsed.print(Some(options));
        }
    }
}
