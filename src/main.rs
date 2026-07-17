mod ethertypes;
mod parser;
mod ports;
mod cli;

use clap::Parser;
use pcap::Capture;
use crate::{cli::Args, parser::DisplayPacketOptions};

fn main() {
    let args = Args::parse();

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
