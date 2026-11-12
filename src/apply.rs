//! Making the node what the plan says, with the established tools so every step can be read and done by hand:
//! `ip` (the interface and its routes), `wg` (its key and peers) and `nft` (the table `freightdock`). What the node
//! has is read back from them each time, so a change made by hand, or a reboot, is put right at the next state.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use freightdock_proto::v1;

use crate::plan::{Change, Have, IFACE, Peer, plan, ruleset, want};

/// WireGuard's port on every node.
pub const WG_PORT: u16 = 51820;

/// Runs a program and gives back what it printed; an exit other than 0 is an error with what it wrote to stderr.
pub trait Run {
    fn run(&mut self, prog: &str, args: &[&str], stdin: Option<&str>) -> Result<String>;
}

/// The real one.
pub struct System;

impl Run for System {
    fn run(&mut self, prog: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(prog).args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().with_context(|| format!("running {prog}"))?;
        if let Some(text) = stdin {
            child.stdin.take().context("no stdin")?.write_all(text.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// The overlay on this node.
pub struct Agent<R: Run> {
    run: R,
    /// The node's private key (`key::Key`'s file), handed to `wg` by path so it is never on a command line.
    key_path: PathBuf,
    /// The ruleset last loaded: loaded again only when the state makes another.
    rules: Option<String>,
}

impl<R: Run> Agent<R> {
    pub fn new(run: R, key_path: PathBuf) -> Self {
        Agent { run, key_path, rules: None }
    }

    /// Makes the node's overlay what `s` says: the interface up with the key, port and MTU, the peers and routes
    /// diffed, the nftables table replaced when it differs. Refused whole, before anything is touched, when the state
    /// could reach outside the cluster's range. Gives back the changes made to peers and routes.
    pub fn apply(&mut self, s: &v1::NetworkState) -> Result<Vec<Change>> {
        let w = want(s)?;
        let rules = ruleset(s)?;
        self.interface(if s.mtu == 0 { 1420 } else { s.mtu })?;
        let changes = plan(&w, &self.have()?);
        for c in &changes {
            self.change(c)?;
        }
        if self.rules.as_deref() != Some(rules.as_str()) {
            // Made first so the delete never fails, then deleted and loaded again in one transaction.
            let text = format!("table inet freightdock\ndelete table inet freightdock\n{rules}");
            self.run.run("nft", &["-f", "-"], Some(&text))?;
            self.rules = Some(rules);
        }
        Ok(changes)
    }

    /// A stack's bridge answers ARP for the stack's addresses on other nodes (they are routed to `fd0`, so the kernel
    /// answers for those only). Called once the bridge is there.
    pub fn proxy_arp(&mut self, bridge: &str) -> Result<()> {
        if bridge.is_empty() || bridge.len() > 15 || !bridge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            bail!("{bridge:?} is not an interface name");
        }
        self.run.run("sysctl", &["-qw", &format!("net.ipv4.conf.{bridge}.proxy_arp=1")], None)?;
        Ok(())
    }

    fn interface(&mut self, mtu: u32) -> Result<()> {
        if self.run.run("ip", &["-o", "link", "show", "dev", IFACE], None).is_err() {
            self.run.run("ip", &["link", "add", IFACE, "type", "wireguard"], None)?;
        }
        let key = self.key_path.to_string_lossy().into_owned();
        self.run.run("wg", &["set", IFACE, "listen-port", &WG_PORT.to_string(), "private-key", &key], None)?;
        self.run.run("ip", &["link", "set", IFACE, "mtu", &mtu.to_string(), "up"], None)?;
        Ok(())
    }

    fn have(&mut self) -> Result<Have> {
        let mut h = Have { peers: parse_dump(&self.run.run("wg", &["show", IFACE, "dump"], None)?), ..Default::default() };
        h.routes = parse_routes(&self.run.run("ip", &["-4", "route", "show", "dev", IFACE], None)?);
        Ok(h)
    }

    fn change(&mut self, c: &Change) -> Result<()> {
        match c {
            Change::SetPeer { key, peer } => {
                let allowed = peer.allowed.iter().cloned().collect::<Vec<_>>().join(",");
                let mut args = vec!["set", IFACE, "peer", key.as_str()];
                if !peer.endpoint.is_empty() {
                    args.extend(["endpoint", peer.endpoint.as_str()]);
                }
                args.extend(["allowed-ips", allowed.as_str()]);
                self.run.run("wg", &args, None)?;
            }
            Change::RemovePeer { key } => {
                self.run.run("wg", &["set", IFACE, "peer", key, "remove"], None)?;
            }
            Change::AddRoute(r) => {
                self.run.run("ip", &["route", "replace", r, "dev", IFACE], None)?;
            }
            Change::RemoveRoute(r) => {
                self.run.run("ip", &["route", "del", r, "dev", IFACE], None)?;
            }
        }
        Ok(())
    }
}

/// `wg show <if> dump`: the interface's line, then a line per peer (key, preshared key, endpoint, allowed IPs,
/// handshake, received, sent, keepalive), tab separated, `(none)` for nothing.
fn parse_dump(text: &str) -> std::collections::BTreeMap<String, Peer> {
    let none = |s: &str| if s == "(none)" { String::new() } else { s.to_string() };
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 4).then(|| (f[0].to_string(), Peer { endpoint: none(f[2]), allowed: none(f[3]).split(',').filter(|a| !a.is_empty()).map(str::to_string).collect() }))
        })
        .collect()
}

/// `ip -4 route show dev <if>`: the destination first on each line, a host route without its `/32`.
fn parse_routes(text: &str) -> std::collections::BTreeSet<String> {
    text.lines().filter_map(|l| l.split_whitespace().next()).map(|d| if d.contains('/') { d.to_string() } else { format!("{d}/32") }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const K1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const K2: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

    /// Answers by command line, fails what it was told to, and keeps every call.
    #[derive(Default)]
    struct Fake {
        out: HashMap<String, String>,
        fail: Vec<String>,
        calls: Vec<String>,
        stdin: Vec<String>,
    }

    impl Run for &mut Fake {
        fn run(&mut self, prog: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
            let line = format!("{prog} {}", args.join(" "));
            self.calls.push(line.clone());
            if let Some(s) = stdin {
                self.stdin.push(s.to_string());
            }
            if self.fail.contains(&line) {
                bail!("no");
            }
            Ok(self.out.get(&line).cloned().unwrap_or_default())
        }
    }

    fn state(peers: &[(&str, &str, &[&str])]) -> v1::NetworkState {
        v1::NetworkState {
            version: 1,
            cluster_range: "10.240.0.0/16".into(),
            mtu: 1420,
            peers: peers.iter().map(|(k, e, a)| v1::NetworkPeer { node_id: "n".into(), public_key: k.to_string(), endpoint: e.to_string(), addresses: a.iter().map(|s| s.to_string()).collect() }).collect(),
            stacks: vec![v1::StackNetwork { stack: "web".into(), subnet: "10.240.1.0/24".into(), gateway: "10.240.1.1".into() }],
        }
    }

    #[test]
    fn what_wg_and_ip_print_is_read_back_as_peers_and_routes() {
        let dump = format!("PRIV\tPUB\t51820\toff\n{K1}\t(none)\t192.0.2.1:51820\t10.240.1.2/32,10.240.1.3/32\t0\t0\t0\toff\n{K2}\t(none)\t(none)\t(none)\t0\t0\t0\toff\n");
        let peers = parse_dump(&dump);
        assert_eq!(peers[K1], Peer { endpoint: "192.0.2.1:51820".into(), allowed: ["10.240.1.2/32".to_string(), "10.240.1.3/32".to_string()].into() });
        assert_eq!(peers[K2], Peer::default());
        let routes = parse_routes("10.240.0.0/16 scope link \n10.240.1.2 scope link \n");
        assert_eq!(routes, ["10.240.0.0/16".to_string(), "10.240.1.2/32".to_string()].into());
    }

    #[test]
    fn a_fresh_node_gets_the_interface_its_peers_routes_and_table() {
        let mut f = Fake { fail: vec!["ip -o link show dev fd0".into()], ..Default::default() };
        let mut a = Agent::new(&mut f, "/var/lib/freightdock-worker/wg.key".into());
        let changes = a.apply(&state(&[(K1, "192.0.2.1:51820", &["10.240.1.2/32"])])).unwrap();
        assert_eq!(changes.len(), 3, "a peer and two routes: {changes:?}");
        let calls = f.calls.clone();
        let at = |c: &str| calls.iter().position(|x| x == c).unwrap_or_else(|| panic!("{c} not in {calls:#?}"));
        assert!(at("ip link add fd0 type wireguard") < at("wg set fd0 listen-port 51820 private-key /var/lib/freightdock-worker/wg.key"));
        at("ip link set fd0 mtu 1420 up");
        assert!(at(&format!("wg set fd0 peer {K1} endpoint 192.0.2.1:51820 allowed-ips 10.240.1.2/32")) < at("ip route replace 10.240.1.2/32 dev fd0"), "the peer before its route");
        at("ip route replace 10.240.0.0/16 dev fd0");
        at("nft -f -");
        assert!(f.stdin[0].starts_with("table inet freightdock\ndelete table inet freightdock\ntable inet freightdock {"), "replaced in one go:\n{}", f.stdin[0]);
        assert!(!f.calls.iter().any(|c| c.contains("AAAA") && c.contains("private")), "the private key is never on a command line");
    }

    #[test]
    fn a_node_as_wanted_is_left_alone_and_the_table_loaded_once() {
        let s = state(&[(K1, "192.0.2.1:51820", &["10.240.1.2/32"])]);
        let mut f = Fake::default();
        f.out.insert("wg show fd0 dump".into(), format!("P\tQ\t51820\toff\n{K1}\t(none)\t192.0.2.1:51820\t10.240.1.2/32\t0\t0\t0\toff\n"));
        f.out.insert("ip -4 route show dev fd0".into(), "10.240.0.0/16 scope link\n10.240.1.2 scope link\n".into());
        let mut a = Agent::new(&mut f, "k".into());
        assert!(a.apply(&s).unwrap().is_empty());
        assert!(a.apply(&s).unwrap().is_empty());
        drop(a);
        assert!(!f.calls.iter().any(|c| c.starts_with("ip link add")), "the interface was there");
        assert_eq!(f.calls.iter().filter(|c| *c == "nft -f -").count(), 1, "the same rules are not loaded again");
    }

    #[test]
    fn a_peer_gone_takes_its_routes_first_and_a_bad_state_touches_nothing() {
        let mut f = Fake::default();
        f.out.insert("wg show fd0 dump".into(), format!("P\tQ\t51820\toff\n{K2}\t(none)\t192.0.2.2:51820\t10.240.1.9/32\t0\t0\t0\toff\n"));
        f.out.insert("ip -4 route show dev fd0".into(), "10.240.0.0/16 scope link\n10.240.1.9 scope link\n".into());
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&state(&[])).unwrap();
        assert!(a.apply(&state(&[(K1, "192.0.2.1:51820", &["192.168.1.5/32"])])).is_err());
        drop(a);
        let at = |c: &str| f.calls.iter().position(|x| x == c).unwrap();
        assert!(at("ip route del 10.240.1.9/32 dev fd0") < at(&format!("wg set fd0 peer {K2} remove")));
        assert!(!f.calls.iter().any(|c| c.contains("192.168.1.5")), "{:#?}", f.calls);
    }

    #[test]
    fn proxy_arp_is_set_on_a_bridge_by_its_name_only() {
        let mut f = Fake::default();
        let mut a = Agent::new(&mut f, "k".into());
        a.proxy_arp("fd-web").unwrap();
        assert!(a.proxy_arp("fd-web/../all").is_err());
        assert!(a.proxy_arp("x y").is_err());
        drop(a);
        assert_eq!(f.calls, vec!["sysctl -qw net.ipv4.conf.fd-web.proxy_arp=1"]);
    }
}
