use colored::Colorize;

use crate::ethertypes::Ethertype;
use crate::parser::{EthernetHeader, IPv4Header, DisplayPacketOptions, ascii_repr};
use crate::ports::Port;
use crate::PORT_TO_PIDS;

pub struct UdpHeader {
    pub src_port: Port,
    pub dst_port: Port,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl UdpHeader {
    pub fn print(&self, show_payload: bool) {
        println!("{}", "[UDP]".magenta().bold());
        println!("  {} {}", "Src Port:".dimmed(), self.src_port);
        println!("  {} {}", "Dst Port:".dimmed(), self.dst_port);
        println!("  {} {}", "Length:".dimmed(), self.length);

        println!("  {} ({} bytes)", "Payload:".dimmed(), self.payload.len());
        if show_payload {
            for (i, chunk) in self.payload.chunks(16).enumerate() {
                let ascii: String = chunk.iter().map(|b| ascii_repr(*b)).collect();
                println!("{:04x}    {:02x?}  |  {}", i*16, chunk, ascii.dimmed());
            }
        }
    }
}

pub struct ParsedUdpPacket {
    pub ethernet: EthernetHeader,
    pub ipv4: IPv4Header,
    pub udp: UdpHeader,
}

impl ParsedUdpPacket {
    pub async fn print(&self, display_options: Option<DisplayPacketOptions>) {
        if let Some(options) = display_options {
            if let Some(filter_pid) = options.filter_by_pid {
                let pid_info = {
                    let map = PORT_TO_PIDS.read().await;
                    map.get(&self.udp.src_port.port)
                        .and_then(|pids| pids.first().copied())
                };
                pid_info.and_then(|extracted_pid| {
                    if extracted_pid == filter_pid {
                        self.ethernet.print();
                        self.ipv4.print();
                        self.udp.print(options.show_payload);
                        Some(())
                    } else {
                        None
                    }
                });
            } else {
                self.ethernet.print();
                self.ipv4.print();
                self.udp.print(options.show_payload);
            }
        } else {
            self.ethernet.print();
            self.ipv4.print();
            self.udp.print(true);
        }
    }
}

pub fn parse_udp_ipv4(data: &[u8]) -> Option<ParsedUdpPacket> {
    if data.len() < 14 { return None; }

    let ethernet = EthernetHeader {
        dst_mac: data[0..6].to_vec(),
        src_mac: data[6..12].to_vec(),
        ethertype: Ethertype::from_ethernet(data),
    };

    let ip = &data[14..];
    if ip.len() < 20 { return None; }

    let ihl = (ip[0] & 0x0f) * 4;

    let ipv4 = IPv4Header {
        src_ip: [ip[12], ip[13], ip[14], ip[15]],
        dst_ip: [ip[16], ip[17], ip[18], ip[19]],
        ttl: ip[8],
        protocol: ip[9],
    };

    if ipv4.protocol != 17 { return None; }

    let total_len = u16::from_be_bytes([ip[2], ip[3]]);
    if ip.len() < total_len as usize { return None; }
    if ip.len() < ihl as usize { return None; }
    let udp = &ip[ihl as usize..];

    if udp.len() < 8 { return None; }

    let udp_length = u16::from_be_bytes([udp[4], udp[5]]);
    let payload = if udp_length as usize > 8 {
        &udp[8..udp_length as usize]
    } else {
        &[]
    };

    let udp_header = UdpHeader {
        src_port: Port::new(u16::from_be_bytes([udp[0], udp[1]])),
        dst_port: Port::new(u16::from_be_bytes([udp[2], udp[3]])),
        length: udp_length,
        checksum: u16::from_be_bytes([udp[6], udp[7]]),
        payload: payload.to_vec(),
    };

    Some(ParsedUdpPacket { ethernet, ipv4, udp: udp_header })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_udp_ipv4_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        packet.extend_from_slice(&[0x08, 0x00]);

        let udp_len = 8 + payload.len() as u16;
        let total_len: u16 = 20 + udp_len;
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&total_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(17);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);

        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);

        packet.extend_from_slice(payload);

        packet
    }

    #[test]
    fn test_parse_valid_udp_ipv4() {
        let payload = b"hello";
        let packet = build_udp_ipv4_packet(12345, 53, payload);
        let parsed = parse_udp_ipv4(&packet).expect("should parse successfully");

        assert_eq!(parsed.udp.src_port.port, 12345);
        assert_eq!(parsed.udp.dst_port.port, 53);
        assert_eq!(parsed.ipv4.src_ip, [10, 0, 0, 1]);
        assert_eq!(parsed.ipv4.dst_ip, [10, 0, 0, 2]);
        assert_eq!(parsed.ipv4.protocol, 17);
        assert_eq!(parsed.udp.length, 8 + 5);
        assert_eq!(parsed.udp.payload, b"hello");
        assert_eq!(parsed.ethernet.ethertype, Ethertype::new(0x0800));
    }

    #[test]
    fn test_parse_udp_empty_payload() {
        let packet = build_udp_ipv4_packet(53, 12345, &[]);
        let parsed = parse_udp_ipv4(&packet).expect("should parse");
        assert_eq!(parsed.udp.payload.len(), 0);
        assert_eq!(parsed.udp.length, 8);
    }

    #[test]
    fn test_parse_udp_too_short_returns_none() {
        assert!(parse_udp_ipv4(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_udp_wrong_protocol_returns_none() {
        let mut packet = build_udp_ipv4_packet(53, 12345, b"test");
        packet[23] = 6;
        assert!(parse_udp_ipv4(&packet).is_none());
    }

    #[test]
    fn test_parse_udp_large_payload() {
        let payload = vec![0xAB; 1400];
        let packet = build_udp_ipv4_packet(40000, 40001, &payload);
        let parsed = parse_udp_ipv4(&packet).expect("should parse");
        assert_eq!(parsed.udp.payload.len(), 1400);
        assert_eq!(parsed.udp.length, 8 + 1400);
    }
}
