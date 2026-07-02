use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::SystemTime;

/// Transport protocol supported by the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Other(_) => "OTHER",
        }
    }
}

/// Direction of traffic relative to the configured local networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
    Local,
    External,
}

/// Unique identifier for a network flow.
///
/// A flow is identified by:
/// - source IP
/// - destination IP
/// - source port
/// - destination port
/// - protocol
#[derive(Debug, Clone, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.protocol == other.protocol
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
        self.protocol.hash(state);
    }
}

/// Information extracted from a single captured packet.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: SystemTime,

    pub flow: FlowKey,

    pub direction: Direction,

    pub packet_count: u64,

    pub byte_count: u64,
}

impl PacketInfo {
    pub fn new(
        flow: FlowKey,
        direction: Direction,
        packet_len: usize,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            flow,
            direction,
            packet_count: 1,
            byte_count: packet_len as u64,
        }
    }
}

/// Aggregated statistics for one flow.
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,

    pub packets: u64,
    pub bytes: u64,

    pub direction: Direction,
}

impl FlowStats {
    pub fn new(packet: &PacketInfo) -> Self {
        Self {
            first_seen: packet.timestamp,
            last_seen: packet.timestamp,
            packets: 1,
            bytes: packet.byte_count,
            direction: packet.direction,
        }
    }

    pub fn update(&mut self, packet: &PacketInfo) {
        self.last_seen = packet.timestamp;
        self.packets += 1;
        self.bytes += packet.byte_count;
    }
}
