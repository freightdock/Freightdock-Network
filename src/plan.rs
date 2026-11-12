//! What to change on the node (pure: no system calls), from the managers' `NetworkState` and what the node has.
//! WireGuard peers and routes are diffed, so a move changes one peer's addresses and one route, and nothing else is
//! touched; the nftables ruleset is whole, made from the state alone, and replaced when its text differs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use freightdock_proto::v1;

/// The overlay's interface on every node.
pub const IFACE: &str = "fd0";
/// The interface the node's floating addresses are on (G10.3): a dummy, so they are the node's own and its LAN
/// interface answers ARP for them, and nothing else about the host's interfaces changes.
pub const EXT_IFACE: &str = "fd-ext";

/// One WireGuard peer as the interface holds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Peer {
    /// `host:port`, empty when the managers do not know where it is.
    pub endpoint: String,
    /// Its addresses, `a.b.c.d/32`.
    pub allowed: BTreeSet<String>,
}

/// The parts of the node the plan covers: the interface's peers by public key, the routes on it and its own
/// addresses (the node's overlay address, G10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Have {
    pub peers: BTreeMap<String, Peer>,
    pub routes: BTreeSet<String>,
    pub addresses: BTreeSet<String>,
}

pub use freightdock_proto::RESERVED_PORTS;

/// A stack's bridge: `fd-<stack>`, or for a stack whose name makes that longer than Linux's 15 characters, `fd-`
/// and twelve hex characters of its name's hash. Always `fd-...`, which the masquerade of what leaves the range
/// leaves alone.
pub fn bridge_name(stack: &str) -> String {
    let n = format!("fd-{stack}");
    if n.len() <= 15 { n } else { format!("fd-{}", &freightdock_proto::sha256_hex(stack.as_bytes())[..12]) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    SetPeer { key: String, peer: Peer },
    RemovePeer { key: String },
    AddRoute(String),
    RemoveRoute(String),
    AddAddress(String),
    RemoveAddress(String),
}

/// The cluster's range, `a.b.0.0/16`: its first two bytes.
fn range(s: &v1::NetworkState) -> Result<[u8; 2]> {
    let Some((ip, "16")) = s.cluster_range.split_once('/') else { bail!("the cluster range {:?} is not a /16", s.cluster_range) };
    let ip: std::net::Ipv4Addr = ip.parse()?;
    let o = ip.octets();
    if o[2] != 0 || o[3] != 0 || o[0] == 0 {
        bail!("the cluster range {:?} is not a /16", s.cluster_range);
    }
    Ok([o[0], o[1]])
}

/// `prefix` as `a.b.c.d/len` inside the range, with that length.
fn inside(r: [u8; 2], prefix: &str, len: &str) -> Result<()> {
    let ok = prefix.split_once('/').is_some_and(|(ip, l)| l == len && ip.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.octets()[..2] == r));
    if !ok {
        bail!("{prefix:?} is not a /{len} in {}.{}.0.0/16", r[0], r[1]);
    }
    Ok(())
}

fn good_key(k: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(k).is_ok_and(|b| b.len() == 32)
}

/// What the managers' state asks of the interface: a peer per other node, a route for the range and for each
/// address on another node. Refused whole if anything in it could reach outside the cluster's range.
pub fn want(s: &v1::NetworkState) -> Result<Have> {
    let r = range(s)?;
    let mut w = Have::default();
    w.routes.insert(s.cluster_range.clone());
    if !s.node_address.is_empty() {
        let a = format!("{}/32", s.node_address);
        inside(r, &a, "32")?;
        if a.split('.').nth(2) != Some("0") {
            bail!("the node's address {} is not in {}.{}.0.0/24", s.node_address, r[0], r[1]);
        }
        w.addresses.insert(a);
    }
    for p in &s.peers {
        if !good_key(&p.public_key) {
            bail!("node {}: {:?} is not a WireGuard key", p.node_id, p.public_key);
        }
        if !p.endpoint.is_empty() && p.endpoint.parse::<std::net::SocketAddr>().is_err() {
            bail!("node {}: the endpoint {:?} is not an address and port", p.node_id, p.endpoint);
        }
        for a in &p.addresses {
            inside(r, a, "32")?;
            w.routes.insert(a.clone());
        }
        w.peers.insert(p.public_key.clone(), Peer { endpoint: p.endpoint.clone(), allowed: p.addresses.iter().cloned().collect() });
    }
    Ok(w)
}

/// The floating addresses `s` gives this node, as `a.b.c.d/32`: each a unicast IPv4 address a LAN could have, never
/// the cluster's range, a loopback, link-local, multicast or broadcast one. Refused whole otherwise.
pub fn floating(s: &v1::NetworkState) -> Result<BTreeSet<String>> {
    let r = range(s)?;
    s.floating.iter().map(|f| Ok(format!("{}/32", lan_address(r, f)?))).collect()
}

/// `f` as a floating address: a unicast IPv4 address a LAN could have, outside the range.
fn lan_address(r: [u8; 2], f: &str) -> Result<std::net::Ipv4Addr> {
    let Ok(ip) = f.parse::<std::net::Ipv4Addr>() else { bail!("the floating address {f:?} is not an IPv4 address") };
    if ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast() || ip.octets()[0] == 0 || ip.octets()[..2] == r {
        bail!("{ip} cannot be a floating address (not a LAN's, or the cluster's own range)");
    }
    Ok(ip)
}

/// The changes that make `have` into `want`, in a safe order: routes away first, then peers away, peers set, routes
/// added, so no route points at a peer that is not there.
pub fn plan(want: &Have, have: &Have) -> Vec<Change> {
    let mut out: Vec<Change> = have.routes.difference(&want.routes).map(|r| Change::RemoveRoute(r.clone())).collect();
    out.extend(have.addresses.difference(&want.addresses).map(|a| Change::RemoveAddress(a.clone())));
    out.extend(want.addresses.difference(&have.addresses).map(|a| Change::AddAddress(a.clone())));
    out.extend(have.peers.keys().filter(|k| !want.peers.contains_key(*k)).map(|k| Change::RemovePeer { key: k.clone() }));
    out.extend(want.peers.iter().filter(|(k, p)| have.peers.get(*k) != Some(p)).map(|(k, p)| Change::SetPeer { key: k.clone(), peer: p.clone() }));
    out.extend(want.routes.difference(&have.routes).map(|r| Change::AddRoute(r.clone())));
    out
}

/// One published port's rule, to its one workload or spread over its workloads at random; `None` with nothing behind
/// it. A Compose file's port matches every local address but the floating ones the node holds (`pool`), so those
/// answer only what was exposed on them; an exposure on a floating address (G10.5) matches that address only.
fn exposure_rule(r: [u8; 2], e: &v1::Exposure, pool: &[std::net::Ipv4Addr]) -> Result<Option<String>> {
    if !matches!(e.protocol.as_str(), "tcp" | "udp") {
        bail!("{:?} is not tcp or udp", e.protocol);
    }
    if e.port == 0 || e.port > 65535 || RESERVED_PORTS.contains(&e.port) {
        bail!("port {} cannot be published (0, above 65535, or the host's own)", e.port);
    }
    let mut to = vec![];
    for t in &e.targets {
        let Some((ip, port)) = t.rsplit_once(':') else { bail!("{t:?} is not address:port") };
        inside(r, &format!("{ip}/32"), "32")?;
        let port: u16 = port.parse().with_context(|| format!("{t:?} is not address:port"))?;
        if port == 0 {
            bail!("{t:?} has port 0");
        }
        to.push((ip.to_string(), port));
    }
    let at = if !e.address.is_empty() {
        format!("ip daddr {}", lan_address(r, &e.address)?)
    } else if pool.is_empty() {
        "fib daddr type local".to_string()
    } else {
        format!("fib daddr type local ip daddr != {{ {} }}", pool.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "))
    };
    let head = format!("{at} {} dport {} dnat ip to", e.protocol, e.port);
    Ok(match to.as_slice() {
        [] => None,
        [(ip, port)] => Some(format!("{head} {ip}:{port}")),
        many => Some(format!("{head} numgen random mod {} map {{ {} }}", many.len(), many.iter().enumerate().map(|(i, (ip, p))| format!("{i} : {ip} . {p}")).collect::<Vec<_>>().join(", "))),
    })
}

/// The node's nftables table, whole. In the forward path: nothing from a stack's bridge but the stack's own
/// addresses; replies, published ports (G10) and the nodes' own addresses pass; otherwise a stack's addresses reach
/// that stack's only, and any other traffic between two addresses of the range is dropped. The published ports are
/// answered on every local address, before Docker's own rules, for the host's own traffic too but loopback (Docker's
/// proxy has that). Traffic forwarded to another node, or from a workload to a published port, is masqueraded so its
/// replies come back the way it went; traffic leaving the range is masqueraded. Only the range is touched; the
/// host's own rules and Docker's are other tables.
pub fn ruleset(s: &v1::NetworkState) -> Result<String> {
    let r = range(s)?;
    let mut stacks: Vec<(&str, &str)> = s.stacks.iter().map(|st| (st.stack.as_str(), st.subnet.as_str())).collect();
    stacks.sort();
    stacks.dedup();
    let range = &s.cluster_range;
    let nodes = format!("{}.{}.0.0/24", r[0], r[1]);
    let mut out = String::from("table inet freightdock {\n  chain forward {\n    type filter hook forward priority filter - 1; policy accept;\n");
    for (stack, sub) in &stacks {
        inside(r, sub, "24")?;
        out.push_str(&format!("    iifname \"{}\" ip saddr != {sub} drop\n", bridge_name(stack)));
    }
    out.push_str(&format!("    ct state established,related accept\n    ct status dnat accept\n    ip saddr {nodes} accept\n"));
    let mut subnets: Vec<&str> = stacks.iter().map(|(_, sub)| *sub).collect();
    subnets.sort();
    subnets.dedup();
    for sub in subnets {
        out.push_str(&format!("    ip saddr {sub} ip daddr {sub} accept\n"));
    }
    out.push_str(&format!("    ip saddr {range} ip daddr {range} drop\n  }}\n"));
    let mut pool = s.floating.iter().map(|f| lan_address(r, f)).collect::<Result<Vec<_>>>()?;
    pool.sort();
    let mut rules = vec![];
    for e in &s.exposures {
        rules.extend(exposure_rule(r, e, &pool)?);
    }
    rules.sort();
    out.push_str("  chain prerouting {\n    type nat hook prerouting priority dstnat - 10; policy accept;\n");
    for rule in &rules {
        out.push_str(&format!("    {rule}\n"));
    }
    out.push_str("  }\n  chain output {\n    type nat hook output priority dstnat - 10; policy accept;\n");
    for rule in &rules {
        out.push_str(&format!("    ip daddr != 127.0.0.0/8 {rule}\n"));
    }
    out.push_str("  }\n");
    // Stack networks have Docker's masquerade off (it would rewrite traffic into the overlay too): what leaves the
    // range for anywhere but a stack bridge or the overlay is masqueraded here.
    out.push_str(&format!("  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    ct status dnat oifname \"fd0\" masquerade\n    ct status dnat ip saddr {range} oifname \"fd-*\" masquerade\n    ip saddr {range} ip daddr != {range} oifname != \"fd-*\" masquerade\n  }}\n}}\n"));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const K2: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

    fn state(peers: &[(&str, &str, &[&str])], stacks: &[(&str, &str)]) -> v1::NetworkState {
        v1::NetworkState {
            version: 7,
            cluster_range: "10.240.0.0/16".into(),
            mtu: 1420,
            peers: peers.iter().map(|(k, e, a)| v1::NetworkPeer { node_id: "n".into(), public_key: k.to_string(), endpoint: e.to_string(), addresses: a.iter().map(|s| s.to_string()).collect() }).collect(),
            stacks: stacks.iter().map(|(n, sub)| v1::StackNetwork { stack: n.to_string(), subnet: sub.to_string(), gateway: String::new() }).collect(),
            node_address: String::new(),
            exposures: vec![],
            floating: vec![],
        }
    }

    fn exposure(port: u32, proto: &str, targets: &[&str]) -> v1::Exposure {
        v1::Exposure { stack: "a".into(), protocol: proto.into(), port, targets: targets.iter().map(|t| t.to_string()).collect(), address: String::new() }
    }

    #[test]
    fn a_floating_address_answers_only_its_own_exposures_and_a_port_is_its_own_there() {
        let mut s = state(&[], &[("a", "10.240.1.0/24")]);
        s.floating = vec!["192.0.2.10".into(), "192.0.2.11".into()];
        let on = |addr: &str, port, t: &str| v1::Exposure { address: addr.into(), ..exposure(port, "tcp", &[t]) };
        s.exposures = vec![exposure(8088, "tcp", &["10.240.1.3:80"]), on("192.0.2.10", 443, "10.240.1.3:8443"), on("192.0.2.11", 443, "10.240.1.4:443")];
        let r = ruleset(&s).unwrap();
        assert!(r.contains("    fib daddr type local ip daddr != { 192.0.2.10, 192.0.2.11 } tcp dport 8088 dnat ip to 10.240.1.3:80\n"), "a Compose port never on the pool:\n{r}");
        assert!(r.contains("    ip daddr 192.0.2.10 tcp dport 443 dnat ip to 10.240.1.3:8443\n"), "{r}");
        assert!(r.contains("    ip daddr 192.0.2.11 tcp dport 443 dnat ip to 10.240.1.4:443\n"), "one port on two addresses:\n{r}");
        assert!(r.contains("    ip daddr != 127.0.0.0/8 ip daddr 192.0.2.10 tcp dport 443 dnat ip to 10.240.1.3:8443\n"), "the host's own traffic too:\n{r}");
        s.floating.clear();
        assert!(ruleset(&s).unwrap().contains("    fib daddr type local tcp dport 8088 dnat"), "nothing to leave out on a node holding none");
        for bad in ["10.240.0.9", "127.0.0.1", "x", "192.0.2.10/32"] {
            s.exposures = vec![on(bad, 443, "10.240.1.3:80")];
            assert!(ruleset(&s).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_published_port_is_answered_on_every_node_and_spread_over_its_workloads() {
        let mut s = state(&[], &[("a", "10.240.1.0/24")]);
        s.exposures = vec![exposure(8088, "tcp", &["10.240.1.3:80", "10.240.1.4:80"]), exposure(5353, "udp", &["10.240.1.3:53"]), exposure(9000, "tcp", &[])];
        let r = ruleset(&s).unwrap();
        assert!(r.contains("type nat hook prerouting priority dstnat - 10;"), "before Docker's own:\n{r}");
        assert!(r.contains("fib daddr type local tcp dport 8088 dnat ip to numgen random mod 2 map { 0 : 10.240.1.3 . 80, 1 : 10.240.1.4 . 80 }"), "{r}");
        assert!(r.contains("fib daddr type local udp dport 5353 dnat ip to 10.240.1.3:53"), "{r}");
        assert!(r.contains("type nat hook output priority dstnat - 10;") && r.contains("ip daddr != 127.0.0.0/8 fib daddr type local tcp dport 8088"), "the host's own, but loopback (Docker's proxy has it):\n{r}");
        assert!(!r.contains("9000"), "nothing behind it: not answered");
        assert!(r.contains(r#"ct status dnat oifname "fd0" masquerade"#), "forwarded to another node: its reply comes back here\n{r}");
        assert!(r.contains(r#"ct status dnat ip saddr 10.240.0.0/16 oifname "fd-*" masquerade"#), "a workload calling a published port, maybe its own\n{r}");
        let bad = |e: v1::Exposure| {
            let mut s = state(&[], &[("a", "10.240.1.0/24")]);
            s.exposures = vec![e];
            ruleset(&s).is_err()
        };
        assert!(bad(exposure(8088, "tcp", &["192.168.1.5:80"])), "a target outside the range");
        assert!(bad(exposure(8088, "sctp", &["10.240.1.3:80"])));
        assert!(bad(exposure(0, "tcp", &["10.240.1.3:80"])));
        assert!(bad(exposure(8088, "tcp", &["10.240.1.3"])), "address and port");
        for port in [22, 7450, 7451, 7452, 51820] {
            assert!(bad(exposure(port, "tcp", &["10.240.1.3:80"])), "{port} is the host's own");
        }
    }

    #[test]
    fn forwarded_and_answered_traffic_passes_and_a_stack_cannot_pretend_to_be_another() {
        let r = ruleset(&state(&[], &[("web", "10.240.1.0/24")])).unwrap();
        let at = |x: &str| r.find(x).unwrap_or_else(|| panic!("{x} not in\n{r}"));
        let drop = at("ip saddr 10.240.0.0/16 ip daddr 10.240.0.0/16 drop");
        assert!(at("ct state established,related accept") < drop, "replies pass");
        assert!(at("ct status dnat accept") < drop, "a published port reaches any stack");
        assert!(at("ip saddr 10.240.0.0/24 accept") < drop, "the nodes' own addresses (what the mesh forwards from)");
        assert!(at(r#"iifname "fd-web" ip saddr != 10.240.1.0/24 drop"#) < at("ct status dnat accept"), "nothing from a stack's bridge but the stack's addresses, first");
    }

    #[test]
    fn the_node_s_own_address_is_on_the_interface() {
        let mut s = state(&[], &[]);
        s.node_address = "10.240.0.7".into();
        assert_eq!(want(&s).unwrap().addresses, ["10.240.0.7/32".to_string()].into());
        s.node_address = "10.240.1.7".into();
        assert!(want(&s).is_err(), "a node's address is in 10.240.0.0/24");
        let have = Have { addresses: ["10.240.0.9/32".to_string()].into(), ..Default::default() };
        s.node_address = "10.240.0.7".into();
        let p = plan(&want(&s).unwrap(), &have);
        assert!(p.contains(&Change::AddAddress("10.240.0.7/32".into())) && p.contains(&Change::RemoveAddress("10.240.0.9/32".into())), "{p:?}");
    }

    #[test]
    fn a_bridge_name_fits_linux_and_starts_with_fd() {
        assert_eq!(bridge_name("web"), "fd-web");
        assert_eq!(bridge_name("twelve-chars"), "fd-twelve-chars");
        let long = bridge_name("a-rather-long-stack-name");
        assert!(long.len() <= 15 && long.starts_with("fd-"), "{long}");
        assert_ne!(long, bridge_name("a-rather-long-stack-name2"));
        assert_eq!(long, bridge_name("a-rather-long-stack-name"), "the same every time");
    }

    #[test]
    fn what_is_wanted_is_a_peer_per_node_and_a_route_per_remote_address_and_the_range() {
        let w = want(&state(&[(K1, "192.0.2.1:51820", &["10.240.1.2/32"]), (K2, "", &[])], &[])).unwrap();
        assert_eq!(w.peers[K1], Peer { endpoint: "192.0.2.1:51820".into(), allowed: ["10.240.1.2/32".to_string()].into() });
        assert_eq!(w.peers[K2], Peer::default(), "a node not heard yet: a peer with no endpoint");
        assert_eq!(w.routes, ["10.240.0.0/16".to_string(), "10.240.1.2/32".to_string()].into());
    }

    #[test]
    fn a_state_that_could_reach_outside_the_range_is_refused() {
        assert!(want(&state(&[(K1, "192.0.2.1:51820", &["192.168.1.5/32"])], &[])).is_err(), "never a route to the host's own network");
        assert!(want(&state(&[(K1, "192.0.2.1:51820", &["10.240.0.0/16"])], &[])).is_err(), "a /32, nothing wider");
        assert!(want(&state(&[("short", "192.0.2.1:51820", &[])], &[])).is_err(), "a WireGuard key");
        assert!(want(&state(&[(K1, "nowhere", &[])], &[])).is_err(), "an endpoint is host:port");
        let mut s = state(&[], &[]);
        s.cluster_range = "0.0.0.0/0".into();
        assert!(want(&s).is_err(), "the range is a /16");
    }

    #[test]
    fn a_move_changes_two_peers_and_nothing_else() {
        let before = want(&state(&[(K1, "192.0.2.1:51820", &["10.240.1.2/32"]), (K2, "192.0.2.2:51820", &[])], &[])).unwrap();
        let after = want(&state(&[(K1, "192.0.2.1:51820", &[]), (K2, "192.0.2.2:51820", &["10.240.1.2/32"])], &[])).unwrap();
        let p = plan(&after, &before);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().all(|c| matches!(c, Change::SetPeer { .. })), "{p:?}");
        assert!(plan(&after, &after).is_empty(), "as wanted: nothing");
    }

    #[test]
    fn peers_and_routes_that_are_not_wanted_go_and_new_ones_come() {
        let have = want(&state(&[(K1, "192.0.2.1:51820", &["10.240.1.2/32"])], &[])).unwrap();
        let w = want(&state(&[(K2, "192.0.2.2:51820", &["10.240.2.2/32"])], &[])).unwrap();
        let p = plan(&w, &have);
        assert!(p.contains(&Change::RemovePeer { key: K1.into() }));
        assert!(p.contains(&Change::SetPeer { key: K2.into(), peer: w.peers[K2].clone() }));
        assert!(p.contains(&Change::RemoveRoute("10.240.1.2/32".into())));
        assert!(p.contains(&Change::AddRoute("10.240.2.2/32".into())));
        assert!(!p.iter().any(|c| matches!(c, Change::AddRoute(r) | Change::RemoveRoute(r) if r == "10.240.0.0/16")), "the range stays");
        let first = |f: fn(&Change) -> bool| p.iter().position(f).unwrap();
        assert!(first(|c| matches!(c, Change::RemoveRoute(_))) < first(|c| matches!(c, Change::RemovePeer { .. })), "routes go before their peer");
    }

    #[test]
    fn the_filter_keeps_each_stack_to_itself_inside_the_range_only() {
        let r = ruleset(&state(&[], &[("a", "10.240.1.0/24"), ("b", "10.240.2.0/24")])).unwrap();
        assert!(r.starts_with("table inet freightdock {"), "a table of its own:\n{r}");
        assert!(r.contains("ip saddr 10.240.1.0/24 ip daddr 10.240.1.0/24 accept"), "{r}");
        assert!(r.contains("ip saddr 10.240.2.0/24 ip daddr 10.240.2.0/24 accept"), "{r}");
        assert!(r.contains("ip saddr 10.240.0.0/16 ip daddr 10.240.0.0/16 drop"), "and the rest of the range dropped:\n{r}");
        assert!(r.contains("type nat hook postrouting priority srcnat;") && r.contains(r#"ip saddr 10.240.0.0/16 ip daddr != 10.240.0.0/16 oifname != "fd-*" masquerade"#), "out to the world masqueraded, never into the overlay:\n{r}");
        assert_eq!(r, ruleset(&state(&[], &[("b", "10.240.2.0/24"), ("a", "10.240.1.0/24")])).unwrap(), "the same text for the same state");
        assert!(ruleset(&state(&[], &[("x", "10.241.0.0/24")])).is_err(), "a subnet outside the range");
    }
}
