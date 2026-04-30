pub fn classify_port(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        123 => "ntp",
        143 => "imap",
        443 => "https",
        587 => "smtp-submission",
        993 => "imaps",
        995 => "pop3s",
        3000 | 5173 | 8000 | 8080 => "dev-http",
        _ => "unknown",
    }
}

pub fn classify_connection(local_port: Option<u16>, remote_port: Option<u16>) -> &'static str {
    for port in [local_port, remote_port].into_iter().flatten() {
        let class = classify_port(port);
        if class != "unknown" {
            return class;
        }
    }

    "unknown"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_ports() {
        assert_eq!(classify_port(22), "ssh");
        assert_eq!(classify_port(443), "https");
        assert_eq!(classify_port(5173), "dev-http");
    }

    #[test]
    fn classifies_connection_by_local_or_remote_port() {
        assert_eq!(classify_connection(Some(49152), Some(443)), "https");
        assert_eq!(classify_connection(Some(22), Some(55122)), "ssh");
        assert_eq!(classify_connection(Some(49152), Some(49153)), "unknown");
    }
}
