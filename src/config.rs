use ipnet::IpNet;
use serde::Deserialize;
use std::{
    error::Error,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct RawConfig {
    interface: String,
    output_directory: String,
    interval_minutes: u64,
    local_networks: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub output_directory: PathBuf,
    pub interval_minutes: u64,
    pub local_networks: Vec<IpNet>,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let text = fs::read_to_string(path)?;

        let raw: RawConfig = toml::from_str(&text)?;

        if raw.interface.trim().is_empty() {
            return Err("interface cannot be empty".into());
        }

        if raw.interval_minutes == 0 {
            return Err("interval_minutes must be greater than zero".into());
        }

        let output_directory = PathBuf::from(raw.output_directory);

        if !output_directory.exists() {
            fs::create_dir_all(&output_directory)?;
        }

        let mut local_networks = Vec::new();

        for cidr in raw.local_networks {
            local_networks.push(cidr.parse::<IpNet>()?);
        }

        Ok(Config {
            interface: raw.interface,
            output_directory,
            interval_minutes: raw.interval_minutes,
            local_networks,
        })
    }

    /// Returns true if the supplied IP belongs to one of the configured
    /// local networks.
    pub fn is_local(&self, ip: IpAddr) -> bool {
        self.local_networks.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_local() {
        let cfg = Config {
            interface: "eth0".to_string(),
            output_directory: PathBuf::from("./logs"),
            interval_minutes: 60,
            local_networks: vec![
                "192.168.1.0/24".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
                "fd00::/8".parse().unwrap(),
            ],
        };

        assert!(cfg.is_local("192.168.1.100".parse().unwrap()));
        assert!(cfg.is_local("10.5.5.5".parse().unwrap()));
        assert!(cfg.is_local("fd00::1".parse().unwrap()));

        assert!(!cfg.is_local("8.8.8.8".parse().unwrap()));
        assert!(!cfg.is_local("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn test_parse_network() {
        let net: IpNet = "192.168.0.0/16".parse().unwrap();
        assert!(net.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!net.contains(&"8.8.8.8".parse().unwrap()));
    }
}
