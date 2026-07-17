use std::fmt;
use pcap::Linktype;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ethertype {
    pub ethertype: u16,
}

impl Ethertype {
    pub const IPV4: Self = Self { ethertype: 0x0800 };
    pub const ARP: Self = Self { ethertype: 0x0806 };
    pub const IPV6: Self = Self { ethertype: 0x86DD };
    pub const VLAN: Self = Self { ethertype: 0x8100 };

    pub fn new(ethertype: u16) -> Self {
        Self { ethertype }
    }

    pub fn from_ethernet(ethernet: &[u8]) -> Self {
        Self {
            ethertype: u16::from_be_bytes([ethernet[12], ethernet[13]]),
        }
    }

    pub fn name(&self) -> &'static str {
        match self.ethertype {
            0x0800 => "IPv4",
            0x0806 => "ARP",
            0x86DD => "IPv6",
            0x8100 => "VLAN",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for Ethertype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04x})", self.name(), self.ethertype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ethernet(ethertype_bytes: [u8; 2]) -> [u8; 14] {
        let mut ethernet = [0u8; 14];
        ethernet[12] = ethertype_bytes[0];
        ethernet[13] = ethertype_bytes[1];
        ethernet
    }

    #[test]
    fn test_from_ethernet_ipv4() {
        let ethernet = make_ethernet([0x08, 0x00]);
        assert_eq!(Ethertype::from_ethernet(&ethernet), Ethertype::IPV4);
    }

    #[test]
    fn test_from_ethernet_arp() {
        let ethernet = make_ethernet([0x08, 0x06]);
        assert_eq!(Ethertype::from_ethernet(&ethernet), Ethertype::ARP);
    }

    #[test]
    fn test_from_ethernet_ipv6() {
        let ethernet = make_ethernet([0x86, 0xDD]);
        assert_eq!(Ethertype::from_ethernet(&ethernet), Ethertype::IPV6);
    }

    #[test]
    fn test_from_ethernet_vlan() {
        let ethernet = make_ethernet([0x81, 0x00]);
        assert_eq!(Ethertype::from_ethernet(&ethernet), Ethertype::VLAN);
    }

    #[test]
    fn test_name() {
        assert_eq!(Ethertype::IPV4.name(), "IPv4");
        assert_eq!(Ethertype::ARP.name(), "ARP");
        assert_eq!(Ethertype::IPV6.name(), "IPv6");
        assert_eq!(Ethertype::VLAN.name(), "VLAN");
        assert_eq!(Ethertype::new(0x1234).name(), "Unknown");
    }

    #[test]
    fn test_display() {
        assert_eq!(Ethertype::IPV4.to_string(), "IPv4 (0x0800)");
        assert_eq!(Ethertype::ARP.to_string(), "ARP (0x0806)");
        assert_eq!(Ethertype::IPV6.to_string(), "IPv6 (0x86dd)");
        assert_eq!(Ethertype::VLAN.to_string(), "VLAN (0x8100)");
        assert_eq!(Ethertype::new(0x1234).to_string(), "Unknown (0x1234)");
    }

    #[test]
    fn test_value() {
        assert_eq!(Ethertype::IPV4.ethertype, 0x0800);
        assert_eq!(Ethertype::ARP.ethertype, 0x0806);
    }
}
