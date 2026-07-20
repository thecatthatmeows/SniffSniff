use std::fmt::Display;
use colored::Colorize;

use crate::ethertypes::Ethertype;
use crate::parser::{EthernetHeader, IPv4Header, DisplayPacketOptions, ascii_repr};
use crate::ports::Port;
use crate::PORT_TO_PIDS;

pub struct TcpFlags {
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    pub fn from_byte(flags: u8) -> Self {
        Self {
            cwr: flags & 0x80 != 0,
            ece: flags & 0x40 != 0,
            urg: flags & 0x20 != 0,
            ack: flags & 0x10 != 0,
            psh: flags & 0x08 != 0,
            rst: flags & 0x04 != 0,
            syn: flags & 0x02 != 0,
            fin: flags & 0x01 != 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.cwr && !self.ece && !self.urg && !self.ack
            && !self.psh && !self.rst && !self.syn && !self.fin
    }

    pub fn print(&self) {
        let mut flags = Vec::new();
        if self.cwr { flags.push("CWR".dimmed().to_string()); }
        if self.ece { flags.push("ECE".dimmed().to_string()); }
        if self.urg { flags.push("URG".magenta().to_string()); }
        if self.ack { flags.push("ACK".green().to_string()); }
        if self.psh { flags.push("PSH".yellow().to_string()); }
        if self.rst { flags.push("RST".red().to_string()); }
        if self.syn { flags.push("SYN".cyan().to_string()); }
        if self.fin { flags.push("FIN".red().to_string()); }
        print!("[{}]", flags.join(", "));
    }
}

pub struct TcpHeader {
    pub src_port: Port,
    pub dst_port: Port,
    pub flags: TcpFlags,
    pub payload: Vec<u8>,
}

impl TcpHeader {
    pub fn print(&self, show_payload: bool) {
        println!("{}", "[TCP]".green().bold());
        println!("  {} {}", "Src Port:".dimmed(), self.src_port);
        println!("  {} {}", "Dst Port:".dimmed(), self.dst_port);
        print!("  {} ", "Flags:".dimmed());
        self.flags.print();
        println!();

        println!("  {} ({} bytes)", "Payload:".dimmed(), self.payload.len());
        if show_payload {
            for (i, chunk) in self.payload.chunks(16).enumerate() {
                let ascii: String = chunk.iter().map(|b| ascii_repr(*b)).collect();
                println!("{:04x}    {:02x?}  |  {}", i*16, chunk, ascii.dimmed());
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData
}

impl Display for TlsContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChangeCipherSpec => write!(f, "Change Cipher Spec"),
            Self::Alert => write!(f, "Alert"),
            Self::Handshake => write!(f, "Handshake"),
            Self::ApplicationData => write!(f, "Application Data")
        }
    }
}

impl TlsContentType {
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }
    }

    pub fn from_payload(payload_data: &[u8]) -> Option<Self> {
        match payload_data[0] {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None
        }
    }
}

pub struct TlsRecord {
    content_type: Option<TlsContentType>,
    version: String,
    length: u16,
}

impl TlsRecord {
    fn get_version_from_payload(tcp_payload: &[u8]) -> String {
        let upper = tcp_payload[1];
        let lower = tcp_payload[2];
        let version = ((upper as u16) << 8) | (lower as u16);

        String::from(match version {
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "Unknown",
        })
    }

    fn get_length_from_payload(tcp_payload: &[u8]) -> u16 {
        u16::from_be_bytes([tcp_payload[3], tcp_payload[4]])
    }

    pub fn from_data(tcp_payload: &[u8]) -> Self {
        Self {
            content_type: TlsContentType::from_payload(tcp_payload),
            version: TlsRecord::get_version_from_payload(tcp_payload),
            length: TlsRecord::get_length_from_payload(tcp_payload),
        }
    }

    pub fn print(&self) {
        println!("{}", "[TLS]".yellow().bold());
        println!("   {} {:?}", "Content Type:".dimmed(), self.content_type);
        println!("   {} {}", "Version:".dimmed(), self.version.yellow());
        println!("   {} {}", "Length:".dimmed(), self.length);
    }
}

pub struct ParsedPacket {
    pub ethernet: EthernetHeader,
    pub ipv4: IPv4Header,
    pub tcp: TcpHeader,
    pub tls: TlsRecord,
}

impl ParsedPacket {
    pub async fn print(&self, display_options: Option<DisplayPacketOptions>) {
        if let Some(options) = display_options {
            if let Some(filter_pid) = options.filter_by_pid {
                let pid_info = {
                    let map = PORT_TO_PIDS.read().await;
                    map.get(&self.tcp.src_port.port)
                        .and_then(|pids| pids.first().copied())
                };
                pid_info.and_then(|extracted_pid| {
                    if extracted_pid == filter_pid {
                        self.ethernet.print();
                        self.ipv4.print();
                        self.tcp.print(options.show_payload);
                        self.tls.print();
                        Some(())
                    } else {
                        None
                    }
                });
            } else {
                self.ethernet.print();
                self.ipv4.print();
                self.tcp.print(options.show_payload);
                self.tls.print();
            }
        } else {
            self.ethernet.print();
            self.ipv4.print();
            self.tcp.print(true);
            self.tls.print();
        }
    }
}

pub fn parse_tcp_ipv4(data: &[u8]) -> Option<ParsedPacket> {
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

    if ipv4.protocol != 6 { return None; }

    let total_len = u16::from_be_bytes([ip[2], ip[3]]);
    if ip.len() < total_len as usize { return None; }
    if ip.len() < ihl as usize { return None; }
    let tcp = &ip[ihl as usize..];

    if tcp.len() < 13 { return None; }
    let tcp_header_len = ((tcp[12] >> 4) * 4) as usize;

    if tcp.len() < tcp_header_len { return None; }

    let payload = &tcp[tcp_header_len..];
    let tcp_header = TcpHeader {
        src_port: Port::new(u16::from_be_bytes([tcp[0], tcp[1]])),
        dst_port: Port::new(u16::from_be_bytes([tcp[2], tcp[3]])),
        flags: TcpFlags::from_byte(tcp[13]),
        payload: payload.to_vec()
    };

    if payload.len() < 5 { return None }
    let tls = TlsRecord::from_data(payload);

    Some(ParsedPacket { ethernet, ipv4, tcp: tcp_header, tls })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tcp_ipv4_packet(
        src_port: u16,
        dst_port: u16,
        flags: u8,
        tls_content_type: u8,
        tls_version: u16,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4

        // IPv4 header (20 bytes, no options)
        let total_len: u16 = 20 + 20 + 5; // IP + TCP + TLS payload
        packet.push(0x45); // version=4, ihl=5
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&total_len.to_be_bytes()); // total length
        packet.extend_from_slice(&[0x00, 0x00]); // identification
        packet.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
        packet.push(64); // TTL
        packet.push(6); // protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // checksum (ignored in test)
        packet.extend_from_slice(&[10, 0, 0, 1]); // src IP
        packet.extend_from_slice(&[10, 0, 0, 2]); // dst IP

        // TCP header (20 bytes minimum)
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack number
        packet.push(0x50); // data offset=5, reserved=0
        packet.push(flags); // flags
        packet.extend_from_slice(&[0x00, 0x00]); // window size
        packet.extend_from_slice(&[0x00, 0x00]); // checksum
        packet.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        // TLS payload (5 bytes minimum)
        packet.push(tls_content_type);
        let version_bytes = tls_version.to_be_bytes();
        packet.extend_from_slice(&version_bytes);
        packet.extend_from_slice(&[0x00, 0x01]); // length: 1 byte

        packet
    }

    #[test]
    fn test_parse_valid_tcp_ipv4() {
        let packet = build_tcp_ipv4_packet(12345, 443, 0x12, 22, 0x0303);
        let parsed = parse_tcp_ipv4(&packet).expect("should parse successfully");

        assert_eq!(parsed.tcp.src_port.port, 12345);
        assert_eq!(parsed.tcp.dst_port.port, 443);
        assert_eq!(parsed.ipv4.src_ip, [10, 0, 0, 1]);
        assert_eq!(parsed.ipv4.dst_ip, [10, 0, 0, 2]);
        assert_eq!(parsed.ipv4.ttl, 64);
        assert_eq!(parsed.ipv4.protocol, 6);
        assert_eq!(parsed.ethernet.ethertype, Ethertype::new(0x0800));
    }

    #[test]
    fn test_parse_syn_packet() {
        let packet = build_tcp_ipv4_packet(80, 54321, 0x02, 22, 0x0303);
        let parsed = parse_tcp_ipv4(&packet).expect("should parse");
        assert!(parsed.tcp.flags.syn);
        assert!(!parsed.tcp.flags.ack);
        assert!(!parsed.tcp.flags.fin);
    }

    #[test]
    fn test_parse_syn_ack_packet() {
        let packet = build_tcp_ipv4_packet(80, 54321, 0x12, 22, 0x0303);
        let parsed = parse_tcp_ipv4(&packet).expect("should parse");
        assert!(parsed.tcp.flags.syn);
        assert!(parsed.tcp.flags.ack);
    }

    #[test]
    fn test_parse_fin_ack_packet() {
        let packet = build_tcp_ipv4_packet(80, 54321, 0x11, 22, 0x0303);
        let parsed = parse_tcp_ipv4(&packet).expect("should parse");
        assert!(parsed.tcp.flags.fin);
        assert!(parsed.tcp.flags.ack);
    }

    #[test]
    fn test_parse_too_short_returns_none() {
        assert!(parse_tcp_ipv4(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_no_ethernet_returns_none() {
        assert!(parse_tcp_ipv4(&[]).is_none());
    }

    #[test]
    fn test_parse_tcp_flags_all_ones() {
        let packet = build_tcp_ipv4_packet(80, 443, 0xFF, 22, 0x0303);
        let parsed = parse_tcp_ipv4(&packet).expect("should parse");
        assert!(parsed.tcp.flags.cwr);
        assert!(parsed.tcp.flags.ece);
        assert!(parsed.tcp.flags.urg);
        assert!(parsed.tcp.flags.ack);
        assert!(parsed.tcp.flags.psh);
        assert!(parsed.tcp.flags.rst);
        assert!(parsed.tcp.flags.syn);
        assert!(parsed.tcp.flags.fin);
    }

    #[test]
    fn test_tcp_flags_from_byte_syn() {
        let flags = TcpFlags::from_byte(0x02);
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);
        assert!(!flags.psh);
        assert!(!flags.urg);
        assert!(!flags.ece);
        assert!(!flags.cwr);
    }

    #[test]
    fn test_tcp_flags_from_byte_ack() {
        let flags = TcpFlags::from_byte(0x10);
        assert!(flags.ack);
        assert!(!flags.syn);
    }

    #[test]
    fn test_tcp_flags_from_byte_all_zero() {
        let flags = TcpFlags::from_byte(0x00);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_tcp_flags_from_byte_all_ones() {
        let flags = TcpFlags::from_byte(0xFF);
        assert!(!flags.is_empty());
        assert!(flags.cwr);
        assert!(flags.ece);
        assert!(flags.urg);
        assert!(flags.ack);
        assert!(flags.psh);
        assert!(flags.rst);
        assert!(flags.syn);
        assert!(flags.fin);
    }

    #[test]
    fn test_tls_from_data_handshake_tls12() {
        let data = [22, 0x03, 0x03, 0x00, 0x01, 0x00]; // Handshake, TLS 1.2, len=1
        let tls = TlsRecord::from_data(&data);
        assert_eq!(tls.content_type, Some(TlsContentType::Handshake));
        assert_eq!(tls.version, "TLS 1.2");
        assert_eq!(tls.length, 1);
    }

    #[test]
    fn test_tls_from_data_application_data_tls13() {
        let data = [23, 0x03, 0x04, 0x00, 0x10, 0x00]; // ApplicationData, TLS 1.3, len=16
        let tls = TlsRecord::from_data(&data);
        assert_eq!(tls.content_type, Some(TlsContentType::ApplicationData));
        assert_eq!(tls.version, "TLS 1.3");
        assert_eq!(tls.length, 16);
    }

    #[test]
    fn test_tls_from_data_alert_tls10() {
        let data = [21, 0x03, 0x01, 0x00, 0x02, 0x00]; // Alert, TLS 1.0, len=2
        let tls = TlsRecord::from_data(&data);
        assert_eq!(tls.content_type, Some(TlsContentType::Alert));
        assert_eq!(tls.version, "TLS 1.0");
    }

    #[test]
    fn test_tls_from_data_change_cipher_spec() {
        let data = [20, 0x03, 0x03, 0x00, 0x00, 0x00]; // ChangeCipherSpec, TLS 1.2
        let tls = TlsRecord::from_data(&data);
        assert_eq!(tls.content_type, Some(TlsContentType::ChangeCipherSpec));
    }

    #[test]
    fn test_tls_from_data_unknown_content_type() {
        let data = [99, 0x03, 0x03, 0x00, 0x00, 0x00]; // unknown type
        let tls = TlsRecord::from_data(&data);
        assert_eq!(tls.content_type, None);
    }

    #[test]
    fn test_tls_from_data_unknown_version() {
        let data = [22, 0x00, 0x00, 0x00, 0x00, 0x00]; // unknown version
        let tls = TlsRecord::from_data(&data);
        assert_eq!(tls.version, "Unknown");
    }

    #[test]
    fn test_tls_content_type_display() {
        assert_eq!(TlsContentType::Handshake.to_string(), "Handshake");
        assert_eq!(TlsContentType::Alert.to_string(), "Alert");
        assert_eq!(TlsContentType::ApplicationData.to_string(), "Application Data");
        assert_eq!(TlsContentType::ChangeCipherSpec.to_string(), "Change Cipher Spec");
    }

    #[test]
    fn test_tls_content_type_to_byte() {
        assert_eq!(TlsContentType::ChangeCipherSpec.to_byte(), 20);
        assert_eq!(TlsContentType::Alert.to_byte(), 21);
        assert_eq!(TlsContentType::Handshake.to_byte(), 22);
        assert_eq!(TlsContentType::ApplicationData.to_byte(), 23);
    }

    #[test]
    fn test_parse_tcp_wrong_protocol_returns_none() {
        let mut packet = build_tcp_ipv4_packet(80, 443, 0x12, 22, 0x0303);
        // change protocol from TCP (6) to UDP (17)
        packet[23] = 17;
        assert!(parse_tcp_ipv4(&packet).is_none());
    }
}
