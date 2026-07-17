use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port {
    pub port: u16,
}

impl Port {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub fn name(&self) -> &'static str {
        match self.port {
            20 => "FTP-Data",
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            67 => "DHCP-Server",
            68 => "DHCP-Client",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            993 => "IMAPS",
            995 => "POP3S",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            8080 => "HTTP-Alt",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        assert_eq!(Port::new(80).name(), "HTTP");
        assert_eq!(Port::new(443).name(), "HTTPS");
        assert_eq!(Port::new(22).name(), "SSH");
        assert_eq!(Port::new(53).name(), "DNS");
        assert_eq!(Port::new(9999).name(), "Unknown");
    }

    #[test]
    fn test_display() {
        assert_eq!(Port::new(80).to_string(), "HTTP (80)");
        assert_eq!(Port::new(443).to_string(), "HTTPS (443)");
    }
}
