//! What to change on the node (pure: no system calls), from the managers' `NetworkState` and what the node has.
//! WireGuard peers and routes are diffed, so a move changes one peer's addresses and one route, and nothing else is
//! touched; the nftables ruleset is whole, made from the state alone, and replaced when its text differs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use freightdock_proto::v1;

/// The overlay's interface on every node.
pub const IFACE: &str = "fd0";

/// One WireGuard peer as the interface holds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Peer {
    /// `host:port`, empty when the managers do not know where it is.
    pub endpoint: String,
    /// Its addresses, `a.b.c.d/32`.
    pub allowed: BTreeSet<String>,
}

/// The parts of the node the plan covers: the interface's peers by public key and the routes on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Have {
    pub peers: BTreeMap<String, Peer>,
    pub routes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    SetPeer { key: String, peer: Peer },
    RemovePeer { key: String },
    AddRoute(String),
    RemoveRoute(String),
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

/// The changes that make `have` into `want`, in a safe order: routes away first, then peers away, peers set, routes
/// added, so no route points at a peer that is not there.
pub fn plan(want: &Have, have: &Have) -> Vec<Change> {
    let mut out: Vec<Change> = have.routes.difference(&want.routes).map(|r| Change::RemoveRoute(r.clone())).collect();
    out.extend(have.peers.keys().filter(|k| !want.peers.contains_key(*k)).map(|k| Change::RemovePeer { key: k.clone() }));
    out.extend(want.peers.iter().filter(|(k, p)| have.peers.get(*k) != Some(p)).map(|(k, p)| Change::SetPeer { key: k.clone(), peer: p.clone() }));
    out.extend(want.routes.difference(&have.routes).map(|r| Change::AddRoute(r.clone())));
    out
}

/// The node's nftables table, whole: in the forward path, a stack's addresses reach that stack's only, and any other
/// traffic between two addresses of the cluster's range is dropped. Only the range is touched; the host's own rules
/// and Docker's are other tables.
pub fn ruleset(s: &v1::NetworkState) -> Result<String> {
    let r = range(s)?;
    let mut subnets: Vec<&str> = s.stacks.iter().map(|st| st.subnet.as_str()).collect();
    subnets.sort();
    subnets.dedup();
    let mut out = String::from("table inet freightdock {\n  chain forward {\n    type filter hook forward priority filter - 1; policy accept;\n");
    for sub in subnets {
        inside(r, sub, "24")?;
        out.push_str(&format!("    ip saddr {sub} ip daddr {sub} accept\n"));
    }
    out.push_str(&format!("    ip saddr {0} ip daddr {0} drop\n  }}\n}}\n", s.cluster_range));
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
        }
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
        assert_eq!(r, ruleset(&state(&[], &[("b", "10.240.2.0/24"), ("a", "10.240.1.0/24")])).unwrap(), "the same text for the same state");
        assert!(ruleset(&state(&[], &[("x", "10.241.0.0/24")])).is_err(), "a subnet outside the range");
    }
}
