use std::fmt::Display;

use crate::ethertypes::Ethertype;
use crate::ports::Port;
use crate::PORT_TO_PIDS;

fn ascii_repr(byte: u8) -> char {
    if byte.is_ascii_graphic() || byte == b' ' {
        byte as char
    } else {
        '.'
    }
}

pub struct EthernetHeader {
    pub dst_mac: Vec<u8>,
    pub src_mac: Vec<u8>,
    pub ethertype: Ethertype,
}

impl EthernetHeader {
    pub fn print(&self) {
        let dst = self.dst_mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        let src = self.src_mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        println!("[Ethernet]");
        println!("  Dst MAC: {}", dst);
        println!("  Src MAC: {}", src);
        println!("  Type: {}", self.ethertype);
    }
}

pub struct IPv4Header {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub ttl: u8,
    pub protocol: u8,
}

impl IPv4Header {
    pub fn print(&self) {
        println!("[IPv4]");
        println!("  Src: {}.{}.{}.{}", self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]);
        println!("  Dst: {}.{}.{}.{}", self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]);
        println!("  TTL: {}", self.ttl);
        println!("  Protocol: {}", self.protocol);
    }
}

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
        if self.cwr { flags.push("CWR"); }
        if self.ece { flags.push("ECE"); }
        if self.urg { flags.push("URG"); }
        if self.ack { flags.push("ACK"); }
        if self.psh { flags.push("PSH"); }
        if self.rst { flags.push("RST"); }
        if self.syn { flags.push("SYN"); }
        if self.fin { flags.push("FIN"); }
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
        println!("[TCP]");
        println!("  Src Port: {}", self.src_port);
        println!("  Dst Port: {}", self.dst_port);
        print!("  Flags: ");
        self.flags.print();
        println!();

        println!("  Payload ({} bytes)", self.payload.len());
        if show_payload {
            for (i, chunk) in self.payload.chunks(16).enumerate() {
                let ascii: String = chunk.iter().map(|b| ascii_repr(*b)).collect();
                println!("{:04x}    {:02x?}  |  {}", i*16, chunk, ascii);
            }
        }
    }
}

#[derive(Debug)]
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
        println!("[TLS]");
        println!("   Content Type: {:?}", self.content_type);
        println!("   Version: {}", self.version);
        println!("   Length: {}", self.length);
    }
}

#[derive(Default)]
pub struct DisplayPacketOptions {
    pub show_payload: bool,
    pub filter_by_uid: Option<u32>,
}

pub struct ParsedPacket {
    pub ethernet: EthernetHeader,
    pub ipv4: IPv4Header,
    pub tcp: TcpHeader,
    pub tls: TlsRecord,
}

impl ParsedPacket {
    pub fn print(&self, display_options: Option<DisplayPacketOptions>) {
        if let Some(options) = display_options {
            self.ethernet.print();
            self.ipv4.print();
            self.tcp.print(options.show_payload);
            self.tls.print();
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
