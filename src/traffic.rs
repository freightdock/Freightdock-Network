//! The node's share of the cluster's traffic (G9.8), from its connection tracking (`conntrack -L -o extended,id`, with
//! `nf_conntrack_acct` on so each connection carries its bytes). Each connection is counted by one node only: the one
//! it started on (a workload of this node to anywhere) or came in on (from outside the cluster, sent to a workload by
//! the mesh's DNAT). The second leg of a connection the mesh forwarded comes from a node's address, and a connection
//! from another node's workload is that node's to count, so both are left out here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::time::Instant;

use freightdock_proto::v1;

/// One tracked connection: its original direction and where the reply comes from (the real destination after DNAT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub id: u64,
    pub protocol: String,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub dport: u16,
    pub reply_src: Ipv4Addr,
    pub reply_sport: u16,
    pub bytes_out: u64,
    pub bytes_in: u64,
    /// The connection's mark: a tunnel's (G10.4) when it came in by one.
    pub mark: u32,
}

/// `conntrack -L -o extended,id`: the tcp and udp connections over IPv4 with their bytes; anything else is skipped.
pub fn parse(text: &str) -> Vec<Conn> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            if w.first() != Some(&"ipv4") {
                return None;
            }
            let protocol = w.get(2).filter(|p| matches!(**p, "tcp" | "udp"))?.to_string();
            let all = |k: &str| w.iter().filter_map(move |x| x.strip_prefix(k).and_then(|v| v.strip_prefix('='))).collect::<Vec<_>>();
            let (src, dst, sport, dport, bytes) = (all("src"), all("dst"), all("sport"), all("dport"), all("bytes"));
            if src.len() < 2 || dst.len() < 2 || sport.len() < 2 || dport.len() < 2 || bytes.len() < 2 {
                return None;
            }
            Some(Conn {
                id: all("id").first()?.parse().ok()?,
                protocol,
                src: src[0].parse().ok()?,
                dst: dst[0].parse().ok()?,
                dport: dport[0].parse().ok()?,
                reply_src: src[1].parse().ok()?,
                reply_sport: sport[1].parse().ok()?,
                bytes_out: bytes[0].parse().ok()?,
                bytes_in: bytes[1].parse().ok()?,
                mark: all("mark").first().and_then(|m| m.parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

/// What the node knows of the overlay's addresses, from its network state: the range, its own address, and the
/// addresses routed to other nodes. An address in the range that is none of those, and no stack's gateway, is a
/// workload of this node.
#[derive(Debug, Clone, Default)]
pub struct Where {
    range: Option<[u8; 2]>,
    own: Option<Ipv4Addr>,
    remote: BTreeSet<Ipv4Addr>,
}

impl Where {
    pub fn of(s: &v1::NetworkState) -> Where {
        let range = s.cluster_range.split_once('/').and_then(|(ip, _)| ip.parse::<Ipv4Addr>().ok()).map(|ip| [ip.octets()[0], ip.octets()[1]]);
        let remote = s.peers.iter().flat_map(|p| &p.addresses).filter_map(|a| a.trim_end_matches("/32").parse().ok()).collect();
        Where { range, own: s.node_address.parse().ok(), remote }
    }

    fn inside(&self, ip: Ipv4Addr) -> bool {
        self.range.is_some_and(|r| ip.octets()[..2] == r)
    }

    fn local_workload(&self, ip: Ipv4Addr) -> bool {
        let o = ip.octets();
        self.inside(ip) && o[2] != 0 && (2..=254).contains(&o[3]) && Some(ip) != self.own && !self.remote.contains(&ip)
    }

    /// Whom a connection is between, if it is this node's to count: (src, dst, port, published port).
    fn ends(&self, c: &Conn) -> Option<(String, String, u16, u16)> {
        // Forwarded here by another node's mesh with the client's address kept: that node counted it.
        if c.mark & !0xff == 0xfd00 {
            return None;
        }
        let natted = c.dst != c.reply_src;
        if self.local_workload(c.src) {
            return Some(if self.inside(c.reply_src) {
                (c.src.to_string(), c.reply_src.to_string(), c.reply_sport, if natted { c.dport } else { 0 })
            } else {
                (c.src.to_string(), String::new(), c.dport, 0)
            });
        }
        (!self.inside(c.src) && self.inside(c.reply_src) && (natted || self.local_workload(c.reply_src))).then(|| (String::new(), c.reply_src.to_string(), c.reply_sport, if natted { c.dport } else { 0 }))
    }
}

/// The bytes each connection had at the last read, so a report holds what moved since.
#[derive(Debug, Default)]
pub struct Meter {
    last: HashMap<u64, (u64, u64)>,
    at: Option<Instant>,
}

impl Meter {
    /// What moved since the last read, added up per ends and port; `now` is when `conns` was read.
    pub fn read(&mut self, conns: &[Conn], w: &Where, now: Instant) -> v1::TrafficReport {
        let mut flows: BTreeMap<(String, String, u16, u16, String), v1::Flow> = BTreeMap::new();
        let mut seen = HashMap::with_capacity(conns.len());
        for c in conns {
            let before = self.last.get(&c.id).copied();
            seen.insert(c.id, (c.bytes_out, c.bytes_in));
            let Some((src, dst, port, published)) = w.ends(c) else { continue };
            // Counters below the last read: the id was given to a new connection.
            let (o, i) = match before {
                Some((o, i)) if o <= c.bytes_out && i <= c.bytes_in => (c.bytes_out - o, c.bytes_in - i),
                _ => (c.bytes_out, c.bytes_in),
            };
            if before.is_some() && o == 0 && i == 0 {
                continue;
            }
            let f = flows.entry((src.clone(), dst.clone(), port, published, c.protocol.clone())).or_insert_with(|| v1::Flow { src, dst, port: port.into(), published_port: published.into(), protocol: c.protocol.clone(), ..Default::default() });
            f.bytes_out += o;
            f.bytes_in += i;
            f.connections += 1;
        }
        let over_ms = self.at.map(|a| now.saturating_duration_since(a).as_millis() as u64).unwrap_or(0);
        self.last = seen;
        self.at = Some(now);
        v1::TrafficReport { flows: flows.into_values().collect(), over_ms }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[allow(clippy::too_many_arguments)]
    fn line(id: u64, p: &str, src: &str, dst: &str, dport: u16, rsrc: &str, rsport: u16, out: u64, inb: u64) -> String {
        format!("ipv4     2 {p}      6 431998 ESTABLISHED src={src} dst={dst} sport=40000 dport={dport} packets=3 bytes={out} src={rsrc} dst={src} sport={rsport} dport=40000 packets=2 bytes={inb} [ASSURED] mark=0 use=1 id={id}")
    }

    fn here() -> Where {
        let s = v1::NetworkState {
            cluster_range: "10.240.0.0/16".into(),
            node_address: "10.240.0.5".into(),
            peers: vec![v1::NetworkPeer { node_id: "w3".into(), public_key: String::new(), endpoint: String::new(), addresses: vec!["10.240.0.4/32".into(), "10.240.1.4/32".into()] }],
            ..Default::default()
        };
        Where::of(&s)
    }

    #[test]
    fn conntrack_s_lines_are_read_with_both_directions_and_the_rest_skipped() {
        let text = [
            line(7, "tcp", "10.240.1.3", "10.240.1.4", 80, "10.240.1.4", 80, 455, 1402),
            "ipv4     2 udp      17 29 src=192.0.2.101 dst=192.0.2.255 sport=1 dport=2 packets=1 bytes=114 [UNREPLIED] src=192.0.2.255 dst=192.0.2.101 sport=2 dport=1 packets=0 bytes=0 mark=0 use=1 id=9".to_string(),
            "ipv4     2 icmp     1 29 src=192.0.2.1 dst=192.0.2.2 type=8 code=0 id=1 packets=1 bytes=84 src=192.0.2.2 dst=192.0.2.1 type=0 code=0 id=1 packets=1 bytes=84 mark=0 use=1 id=10".to_string(),
            "ipv6     10 tcp      6 1 ESTABLISHED src=::1 dst=::1 sport=1 dport=2 packets=1 bytes=1 src=::1 dst=::1 sport=2 dport=1 packets=1 bytes=1 mark=0 use=1 id=11".to_string(),
            "conntrack v1.4.7 (conntrack-tools): 4 flow entries have been shown.".to_string(),
        ]
        .join("\n");
        let c = parse(&text);
        assert_eq!(c.len(), 2, "{c:#?}");
        assert_eq!((c[0].id, c[0].dport, c[0].reply_sport, c[0].bytes_out, c[0].bytes_in), (7, 80, 80, 455, 1402));
        assert_eq!((c[1].protocol.as_str(), c[1].bytes_in), ("udp", 0));
    }

    #[test]
    fn a_connection_is_counted_where_it_started_or_came_in_and_nowhere_else() {
        let w = here();
        let t0 = Instant::now();
        let conns = parse(
            &[
                // From a workload here to one on w3, straight over the overlay.
                line(1, "tcp", "10.240.1.3", "10.240.1.4", 80, "10.240.1.4", 80, 100, 1000),
                // From outside to this node's published 8088, sent to a workload on w3.
                line(2, "tcp", "192.0.2.50", "192.0.2.5", 8088, "10.240.1.4", 80, 200, 2000),
                // From a workload here to the internet, masqueraded.
                line(3, "tcp", "10.240.1.3", "198.51.100.9", 443, "198.51.100.9", 443, 300, 3000),
                // The second leg of w3's mesh forward: from w3's node address. w3 counts it.
                line(4, "tcp", "10.240.0.4", "10.240.1.3", 80, "10.240.1.3", 80, 400, 4000),
                // From w3's workload to one here: w3 counts it.
                line(5, "tcp", "10.240.1.4", "10.240.1.3", 80, "10.240.1.3", 80, 500, 5000),
                // A workload here to a published port on a node's own address.
                line(6, "tcp", "10.240.2.2", "192.0.2.6", 8088, "10.240.1.4", 80, 600, 6000),
                // Routed in from outside without the mesh: counted by the workload's node, here for a workload here...
                line(8, "tcp", "192.0.2.60", "10.240.2.3", 22, "10.240.2.3", 22, 800, 8000),
                // ...and not here for one on w3.
                line(9, "tcp", "192.0.2.60", "10.240.1.4", 22, "10.240.1.4", 22, 900, 9000),
                // Forwarded here by w3's mesh by its tunnel, the client's address kept: w3 counts it.
                line(10, "tcp", "192.0.2.70", "10.240.2.3", 80, "10.240.2.3", 80, 1000, 10000).replace("mark=0", "mark=64772"),
                // LAN broadcast, never NATed into the cluster.
                line(7, "udp", "192.0.2.101", "192.0.2.255", 9, "192.0.2.255", 9, 700, 0),
            ]
            .join("\n"),
        );
        let r = Meter::default().read(&conns, &w, t0);
        let got: Vec<(&str, &str, u32, u32, u64)> = r.flows.iter().map(|f| (f.src.as_str(), f.dst.as_str(), f.port, f.published_port, f.bytes_out)).collect();
        assert_eq!(got, vec![("", "10.240.1.4", 80, 8088, 200), ("", "10.240.2.3", 22, 0, 800), ("10.240.1.3", "", 443, 0, 300), ("10.240.1.3", "10.240.1.4", 80, 0, 100), ("10.240.2.2", "10.240.1.4", 80, 8088, 600)]);
        assert_eq!(r.over_ms, 0, "the first read covers no time yet");
    }

    #[test]
    fn a_report_holds_what_moved_since_the_last_one_added_up_per_ends() {
        let w = here();
        let mut m = Meter::default();
        let t0 = Instant::now();
        let a = |id, out, inb| line(id, "tcp", "10.240.1.3", "10.240.1.4", 80, "10.240.1.4", 80, out, inb);
        m.read(&parse(&[a(1, 100, 1000), a(2, 50, 500)].join("\n")), &w, t0);
        let r = m.read(&parse(&[a(1, 150, 1600), a(2, 50, 500), a(3, 10, 20)].join("\n")), &w, t0 + Duration::from_secs(5));
        assert_eq!(r.over_ms, 5000);
        assert_eq!(r.flows.len(), 1, "one pair of ends and port");
        let f = &r.flows[0];
        assert_eq!((f.bytes_out, f.bytes_in), (60, 620), "50 + 10 out, 600 + 20 in");
        assert_eq!(f.connections, 2, "the idle one is not counted");
        let r = m.read(&parse(&a(1, 5, 5)), &w, t0 + Duration::from_secs(10));
        assert_eq!((r.flows[0].bytes_out, r.flows[0].bytes_in), (5, 5), "counters went back: a new connection under an old id");
        assert!(m.read(&[], &w, t0 + Duration::from_secs(15)).flows.is_empty());
    }
}
