use chrono::{DateTime, Duration, Local};
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use ipnet::IpNet;
use pcap::{Capture, Device};

use serde::Deserialize;

use std::{
    collections::HashMap,
    error::Error,
    fs::{self, OpenOptions},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

#[derive(Debug, Deserialize)]
struct Config {
    interface: String,
    output_directory: String,
    interval_minutes: u64,
    local_networks: Vec<String>,
}

impl Config {

    fn load() -> Result<Self, Box<dyn Error>> {

        let text = fs::read_to_string("config.toml")?;

        Ok(toml::from_str(&text)?)
    }

    fn networks(&self) -> Vec<IpNet> {

        self.local_networks
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()

    }
}

#[derive(Debug)]
struct PacketInfo {

    timestamp: DateTime<Local>,

    src_ip: IpAddr,

    dst_ip: IpAddr,

    protocol: String,

    src_port: u16,

    dst_port: u16,

    bytes: u64,

}

#[derive(Hash, Eq, PartialEq, Clone)]
struct FlowKey {

    direction: String,

    src_ip: IpAddr,

    dst_ip: IpAddr,

    protocol: String,

    src_port: u16,

    dst_port: u16,

}

#[derive(Default)]
struct FlowStat {

    packets: u64,

    bytes: u64,

}

fn direction(
    src: IpAddr,
    dst: IpAddr,
    nets: &[IpNet],
) -> String {

    let src_local =
        nets.iter().any(|n| n.contains(&src));

    let dst_local =
        nets.iter().any(|n| n.contains(&dst));

    match (src_local, dst_local) {

        (true, true) =>
            "Local".to_string(),

        (true, false) =>
            "Outbound".to_string(),

        (false, true) =>
            "Inbound".to_string(),

        (false, false) =>
            "External".to_string(),
    }

}

fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    let headers = PacketHeaders::from_ethernet_slice(data).ok()?;

    let (src_ip, dst_ip, protocol) = match headers.net? {
        NetHeaders::Ipv4(ip, _) => (
            IpAddr::V4(Ipv4Addr::from(ip.source)),
            IpAddr::V4(Ipv4Addr::from(ip.destination)),
            format!("{:?}", ip.protocol),
        ),

        NetHeaders::Ipv6(ip, _) => (
            IpAddr::V6(Ipv6Addr::from(ip.source)),
            IpAddr::V6(Ipv6Addr::from(ip.destination)),
            format!("{:?}", ip.next_header),
        ),

        _ => return None,
    };

    let (src_port, dst_port, protocol) = match headers.transport {
        Some(TransportHeader::Tcp(tcp)) => (
            tcp.source_port,
            tcp.destination_port,
            "TCP".to_string(),
        ),

        Some(TransportHeader::Udp(udp)) => (
            udp.source_port,
            udp.destination_port,
            "UDP".to_string(),
        ),

        Some(TransportHeader::Icmpv4(_)) => (
            0,
            0,
            "ICMP".to_string(),
        ),

        Some(TransportHeader::Icmpv6(_)) => (
            0,
            0,
            "ICMPv6".to_string(),
        ),

        None => (
            0,
            0,
            protocol,
        ),
    };

    Some(PacketInfo {
        timestamp: Local::now(),
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        bytes: data.len() as u64,
    })
}

fn csv_file(dir: &str) -> PathBuf {
    let name = format!(
        "traffic-{}.csv",
        Local::now().format("%Y-%m-%d")
    );

    PathBuf::from(dir).join(name)
}

fn ensure_csv_header(path: &PathBuf) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        return Ok(());
    }

    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record(&[
        "start_time",
        "end_time",
        "direction",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "packets",
        "bytes",
    ])?;

    wtr.flush()?;

    Ok(())
}


fn flush_csv(
    output_dir: &str,
    start: DateTime<Local>,
    end: DateTime<Local>,
    flows: &HashMap<FlowKey, FlowStat>,
) -> Result<(), Box<dyn Error>> {

    if flows.is_empty() {
        return Ok(());
    }

    let path = csv_file(output_dir);

    ensure_csv_header(&path)?;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(file);

    for (key, stat) in flows {

        writer.write_record(&[
            start.format("%Y-%m-%d %H:%M:%S").to_string(),
            end.format("%Y-%m-%d %H:%M:%S").to_string(),

            key.direction.clone(),

            key.src_ip.to_string(),
            key.dst_ip.to_string(),

            key.protocol.clone(),

            key.src_port.to_string(),
            key.dst_port.to_string(),

            stat.packets.to_string(),
            stat.bytes.to_string(),
        ])?;

    }

    writer.flush()?;

    Ok(())
}

fn update_flow(
    packet: PacketInfo,
    local_networks: &[IpNet],
    flows: &mut HashMap<FlowKey, FlowStat>,
) {

    let key = FlowKey {

        direction: direction(
            packet.src_ip,
            packet.dst_ip,
            local_networks,
        ),

        src_ip: packet.src_ip,

        dst_ip: packet.dst_ip,

        protocol: packet.protocol,

        src_port: packet.src_port,

        dst_port: packet.dst_port,

    };

    let stat = flows
        .entry(key)
        .or_insert_with(FlowStat::default);

    stat.packets += 1;

    stat.bytes += packet.bytes;

}

fn should_flush(
    started: DateTime<Local>,
    interval_minutes: u64,
) -> bool {

    Local::now() >= started + Duration::minutes(interval_minutes as i64)

}

