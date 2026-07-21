use colored::Colorize;
use pcap::{Capture, Active, Offline, Packet};

use crate::ethertypes::Ethertype;

pub use crate::tcp::parse_tcp_ipv4;
pub use crate::udp::parse_udp_ipv4;

pub fn ascii_repr(byte: u8) -> char {
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
        println!("{}", "[Ethernet]".cyan().bold());
        println!("  {} {}", "Dst MAC:".dimmed(), dst.cyan());
        println!("  {} {}", "Src MAC:".dimmed(), src.cyan());
        println!("  {} {}", "Type:".dimmed(), self.ethertype);
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
        println!("{}", "[IPv4]".blue().bold());
        println!("  {} {}.{}.{}.{}", "Src:".dimmed(), self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]);
        println!("  {} {}.{}.{}.{}", "Dst:".dimmed(), self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]);
        println!("  {} {}", "TTL:".dimmed(), self.ttl);
        println!("  {} {}", "Protocol:".dimmed(), self.protocol);
    }
}

#[derive(Default)]
pub struct DisplayPacketOptions {
    pub show_payload: bool,
    pub filter_by_pid: Option<u32>,
}

pub fn parse_ethernet_and_ipv4(data: &[u8]) -> Option<(EthernetHeader, IPv4Header, u8)> {
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

    Some((ethernet, ipv4, ihl))
}

pub enum PacketCapture {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl PacketCapture {
    pub fn next_packet(&mut self) -> Result<Packet<'_>, pcap::Error> {
        match self {
            Self::Live(c) => c.next_packet(),
            Self::File(c) => c.next_packet(),
        }
    }

    pub fn get_datalink(&self) -> pcap::Linktype {
        match self {
            Self::Live(c) => c.get_datalink(),
            Self::File(c) => c.get_datalink(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    #[test]
    fn test_port_lookup_in_map() {
        let mut map: HashMap<u16, Vec<u32>> = HashMap::new();
        map.insert(443, vec![1234]);
        map.insert(80, vec![5678, 9012]);

        assert_eq!(map.get(&443).and_then(|pids| pids.first().copied()), Some(1234));
        assert_eq!(map.get(&80).and_then(|pids| pids.first().copied()), Some(5678));
        assert_eq!(map.get(&9999).and_then(|pids| pids.first().copied()), None);
    }

    #[test]
    fn test_port_lookup_src_or_dst() {
        let mut map: HashMap<u16, Vec<u32>> = HashMap::new();
        map.insert(80, vec![100]);
        map.insert(443, vec![200]);

        let src_port = 12345u16;
        let dst_port = 443u16;

        let pid = map.get(&src_port)
            .or_else(|| map.get(&dst_port))
            .and_then(|pids| pids.first().copied());

        assert_eq!(pid, Some(200));
    }

    #[test]
    fn test_port_lookup_no_match() {
        let map: HashMap<u16, Vec<u32>> = HashMap::new();

        let pid = map.get(&80u16)
            .or_else(|| map.get(&443u16))
            .and_then(|pids| pids.first().copied());

        assert_eq!(pid, None);
    }

    #[test]
    fn test_port_lookup_multiple_pids() {
        let mut map: HashMap<u16, Vec<u32>> = HashMap::new();
        map.insert(80, vec![100, 200, 300]);

        let pid = map.get(&80u16).and_then(|pids| pids.first().copied());
        assert_eq!(pid, Some(100));
    }

    #[test]
    fn test_port_lookup_shared_port() {
        let mut map: HashMap<u16, Vec<u32>> = HashMap::new();
        map.entry(80).or_default().extend([100, 200]);

        assert_eq!(map.get(&80).unwrap(), &vec![100, 200]);
    }
}
