//! Making the node what the plan says, with the established tools so every step can be read and done by hand:
//! `ip` (the interface and its routes), `wg` (its key and peers) and `nft` (the table `freightdock`). What the node
//! has is read back from them each time, so a change made by hand, or a reboot, is put right at the next state.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use freightdock_proto::v1;

use crate::plan::{Change, EXT_IFACE, Have, IFACE, Peer, TUNNEL_PREFIX, Tunnel, floating, plan, ruleset, tunnel_mark, want};

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
    /// The floating addresses announced on the LAN since they came here; one whose announcement failed is tried
    /// again at the next state.
    announced: BTreeSet<String>,
    /// The overlay's addresses as the last state applied gave them, and the bytes counted so far (G9.8).
    seen: crate::traffic::Where,
    meter: crate::traffic::Meter,
    accounting: bool,
}

impl<R: Run> Agent<R> {
    pub fn new(run: R, key_path: PathBuf) -> Self {
        Agent { run, key_path, rules: None, announced: BTreeSet::new(), seen: Default::default(), meter: Default::default(), accounting: false }
    }

    /// Makes the node's overlay what `s` says: the interface up with the key, port and MTU, the peers and routes
    /// diffed, the nftables table replaced when it differs. Refused whole, before anything is touched, when the state
    /// could reach outside the cluster's range. Gives back the changes made to peers and routes.
    pub fn apply(&mut self, s: &v1::NetworkState) -> Result<Vec<Change>> {
        let w = want(s)?;
        let rules = ruleset(s)?;
        let float = floating(s)?;
        self.interface(if s.mtu == 0 { 1420 } else { s.mtu })?;
        let changes = plan(&w, &self.have()?);
        self.docker_user()?;
        for c in &changes {
            self.change(c)?;
        }
        if self.rules.as_deref() != Some(rules.as_str()) {
            // Made first so the delete never fails, then deleted and loaded again in one transaction.
            let text = format!("table inet freightdock\ndelete table inet freightdock\n{rules}");
            self.run.run("nft", &["-f", "-"], Some(&text))?;
            self.rules = Some(rules);
        }
        self.floating(&float)?;
        self.seen = crate::traffic::Where::of(s);
        Ok(changes)
    }

    /// The node's share of the traffic since the last call (`traffic`): connection tracking read with its byte
    /// counters, switched on the first time (`nf_conntrack_acct`, so connections from then on carry their bytes).
    pub fn traffic(&mut self) -> Result<v1::TrafficReport> {
        if !self.accounting {
            self.run.run("sysctl", &["-qw", "net.netfilter.nf_conntrack_acct=1"], None)?;
            self.accounting = true;
        }
        let text = self.run.run("conntrack", &["-L", "-o", "extended,id"], None)?;
        Ok(self.meter.read(&crate::traffic::parse(&text), &self.seen, std::time::Instant::now()))
    }

    /// Takes every floating address off the node: it fenced itself, and the managers may give them to another.
    pub fn drop_floating(&mut self) -> Result<()> {
        self.announced.clear();
        if self.run.run("ip", &["-o", "link", "show", "dev", EXT_IFACE], None).is_ok() {
            self.run.run("ip", &["addr", "flush", "dev", EXT_IFACE], None)?;
        }
        Ok(())
    }

    /// The floating addresses on `fd-ext`, each new one announced with a gratuitous ARP on the interface its LAN is
    /// on, so the LAN's switches and hosts learn at once that it is here now.
    fn floating(&mut self, want: &BTreeSet<String>) -> Result<()> {
        if self.run.run("ip", &["-o", "link", "show", "dev", EXT_IFACE], None).is_err() {
            if want.is_empty() {
                return Ok(());
            }
            self.run.run("ip", &["link", "add", EXT_IFACE, "type", "dummy"], None)?;
        }
        self.run.run("ip", &["link", "set", EXT_IFACE, "up"], None)?;
        let have = parse_addresses(&self.run.run("ip", &["-4", "-o", "addr", "show", "dev", EXT_IFACE], None)?);
        for a in have.difference(want) {
            self.run.run("ip", &["addr", "del", a, "dev", EXT_IFACE], None)?;
        }
        for a in want.difference(&have) {
            self.run.run("ip", &["addr", "add", a, "dev", EXT_IFACE], None)?;
        }
        self.announced.retain(|a| want.contains(a));
        for a in want.difference(&self.announced.clone()) {
            let ip = a.trim_end_matches("/32");
            let dev = self.lan_of(ip)?;
            self.run.run("arping", &["-U", "-c", "2", "-I", &dev, ip], None).with_context(|| format!("announcing {ip} on {dev}"))?;
            self.announced.insert(a.clone());
        }
        Ok(())
    }

    /// The interface whose network holds `ip`, else the default route's.
    fn lan_of(&mut self, ip: &str) -> Result<String> {
        let ip: std::net::Ipv4Addr = ip.parse()?;
        let lines = self.run.run("ip", &["-4", "-o", "addr", "show"], None)?;
        if let Some(dev) = lan_holding(&lines, ip) {
            return Ok(dev);
        }
        let d = self.run.run("ip", &["-4", "route", "show", "default"], None)?;
        d.split_whitespace().skip_while(|w| *w != "dev").nth(1).map(str::to_string).with_context(|| format!("no interface for {ip}: no LAN holds it and there is no default route"))
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

    /// Forgets what a container (by its process, `pid`) knows of `addr`'s MAC: an address that left this node was
    /// answered by its own container, and a peer that kept that answer waits for it to fail (some seconds) before it
    /// asks again and the host answers for the address's new node. Called when that container is removed.
    pub fn forget_neighbour(&mut self, pid: u32, addr: &str) -> Result<()> {
        if pid == 0 {
            bail!("pid 0 is no container's");
        }
        let ip: std::net::Ipv4Addr = addr.parse().with_context(|| format!("{addr:?} is not an IPv4 address"))?;
        self.run.run("nsenter", &["-t", &pid.to_string(), "-n", "ip", "neigh", "flush", "to", &ip.to_string()], None)?;
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
        h.addresses = parse_addresses(&self.run.run("ip", &["-4", "-o", "addr", "show", "dev", IFACE], None)?);
        h.tunnels = parse_tunnels(&self.run.run("ip", &["-d", "-o", "link", "show", "type", "ipip"], None)?);
        Ok(h)
    }

    /// Docker drops in its FORWARD chain what it did not publish itself; the mesh's forwarded connections into the
    /// overlay and their replies are let through in `DOCKER-USER`, the chain Docker keeps for its users and never
    /// flushes. Added once, only where Docker is.
    fn docker_user(&mut self) -> Result<()> {
        if self.run.run("iptables", &["-S", "DOCKER-USER"], None).is_err() {
            return Ok(());
        }
        let tunnels = format!("{TUNNEL_PREFIX}+");
        let t = tunnels.as_str();
        for rule in [
            ["-o", IFACE, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"],
            ["-i", IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["-o", t, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"],
            ["-i", t, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ] {
            let check: Vec<&str> = ["-C", "DOCKER-USER"].into_iter().chain(rule).collect();
            if self.run.run("iptables", &check, None).is_err() {
                let add: Vec<&str> = ["-I", "DOCKER-USER"].into_iter().chain(rule).collect();
                self.run.run("iptables", &add, None)?;
            }
        }
        Ok(())
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
            Change::AddAddress(a) => {
                self.run.run("ip", &["addr", "add", a, "dev", IFACE], None)?;
            }
            Change::RemoveAddress(a) => {
                self.run.run("ip", &["addr", "del", a, "dev", IFACE], None)?;
            }
            Change::AddTunnel { name, tunnel } => {
                let mark = tunnel_mark(&tunnel.remote).context("a tunnel to a node's address")?;
                let (m, table) = (format!("{mark:#x}"), mark.to_string());
                self.run.run("ip", &["link", "add", name, "type", "ipip", "local", &tunnel.local, "remote", &tunnel.remote], None)?;
                self.run.run("ip", &["link", "set", name, "mtu", &tunnel.mtu.to_string(), "up"], None)?;
                // An interface with no address of its own forwards nothing it receives.
                self.run.run("ip", &["addr", "add", &format!("{}/32", tunnel.local), "dev", name], None)?;
                // The replies come in by the tunnel from a workload whose route is the overlay's: loose.
                self.run.run("sysctl", &["-qw", &format!("net.ipv4.conf.{name}.rp_filter=2")], None)?;
                self.run.run("ip", &["route", "replace", "default", "dev", name, "table", &table], None)?;
                let _ = self.run.run("ip", &["rule", "del", "fwmark", &m, "lookup", &table], None);
                self.run.run("ip", &["rule", "add", "fwmark", &m, "lookup", &table, "pref", "1000"], None)?;
            }
            Change::RemoveTunnel(name) => {
                if let Some(mark) = name.strip_prefix(TUNNEL_PREFIX).and_then(|n| n.parse::<u32>().ok()).map(|n| 0xfd00 | n) {
                    let _ = self.run.run("ip", &["rule", "del", "fwmark", &format!("{mark:#x}"), "lookup", &mark.to_string()], None);
                }
                self.run.run("ip", &["link", "del", name], None)?;
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

/// `ip -4 -o addr show`: the interface (not the loopback nor one of ours) whose network holds `ip`.
fn lan_holding(text: &str, ip: std::net::Ipv4Addr) -> Option<String> {
    text.lines().find_map(|l| {
        let w: Vec<&str> = l.split_whitespace().collect();
        let dev = w.get(1)?;
        let (a, len) = w.iter().skip_while(|x| **x != "inet").nth(1)?.split_once('/')?;
        let (a, len): (std::net::Ipv4Addr, u32) = (a.parse().ok()?, len.parse().ok()?);
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32)) };
        (*dev != "lo" && !dev.starts_with("fd") && len < 32 && u32::from(a) & mask == u32::from(ip) & mask).then(|| dev.to_string())
    })
}

/// `ip -d -o link show type ipip`: our tunnels (`fdt-...`), each with its two ends and MTU.
fn parse_tunnels(text: &str) -> std::collections::BTreeMap<String, Tunnel> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let name = w.get(1)?.trim_end_matches(':').split('@').next()?;
            if !name.starts_with(TUNNEL_PREFIX) {
                return None;
            }
            let after = |k: &str| w.iter().position(|x| *x == k).and_then(|i| w.get(i + 1)).map(|v| v.to_string());
            Some((name.to_string(), Tunnel { local: after("link/ipip")?, remote: after("peer")?, mtu: after("mtu")?.parse().ok()? }))
        })
        .collect()
}

/// `ip -4 -o addr show dev <if>`: the address after `inet` on each line.
fn parse_addresses(text: &str) -> std::collections::BTreeSet<String> {
    text.lines().filter_map(|l| l.split_whitespace().skip_while(|w| *w != "inet").nth(1)).map(str::to_string).collect()
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
            node_address: "10.240.0.7".into(),
            exposures: vec![],
            floating: vec![],
        }
    }

    fn floating(f: &[&str]) -> v1::NetworkState {
        v1::NetworkState { floating: f.iter().map(|s| s.to_string()).collect(), ..state(&[]) }
    }

    const LAN: &str = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0\\       valid_lft forever\n5: fd0    inet 10.240.0.7/32 scope global fd0\\       valid_lft forever\n";

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
        assert_eq!(changes.len(), 4, "a peer, two routes and the node's address: {changes:?}");
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
        f.out.insert("ip -4 -o addr show dev fd0".into(), "5: fd0    inet 10.240.0.7/32 scope global fd0\\       valid_lft forever preferred_lft forever\n".into());
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
    fn a_neighbour_is_forgotten_inside_a_container_s_network_only_for_an_address() {
        let mut f = Fake::default();
        let mut a = Agent::new(&mut f, "k".into());
        a.forget_neighbour(4242, "10.240.5.3").unwrap();
        assert!(a.forget_neighbour(4242, "10.240.5.3; reboot").is_err());
        assert!(a.forget_neighbour(0, "10.240.5.3").is_err(), "pid 0 is no container");
        drop(a);
        assert_eq!(f.calls, vec!["nsenter -t 4242 -n ip neigh flush to 10.240.5.3"]);
    }

    #[test]
    fn docker_lets_through_what_the_mesh_forwards_and_its_replies_once() {
        let mut f = Fake { fail: vec!["iptables -C DOCKER-USER -o fd0 -m conntrack --ctstate DNAT -j ACCEPT".into(), "iptables -C DOCKER-USER -i fd0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".into()], ..Default::default() };
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&state(&[])).unwrap();
        drop(a);
        assert!(f.calls.contains(&"iptables -I DOCKER-USER -o fd0 -m conntrack --ctstate DNAT -j ACCEPT".to_string()), "{:#?}", f.calls);
        assert!(f.calls.contains(&"iptables -I DOCKER-USER -i fd0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string()));
        assert!(f.calls.contains(&"ip addr add 10.240.0.7/32 dev fd0".to_string()), "the node's own address");
        let mut f = Fake::default();
        Agent::new(&mut f, "k".into()).apply(&state(&[])).unwrap();
        assert!(!f.calls.iter().any(|c| c.starts_with("iptables -I")), "there already: not added twice");
        let mut f = Fake { fail: vec!["iptables -S DOCKER-USER".into()], ..Default::default() };
        Agent::new(&mut f, "k".into()).apply(&state(&[])).unwrap();
        assert!(!f.calls.iter().any(|c| c.starts_with("iptables -C") || c.starts_with("iptables -I")), "no Docker, nothing to let through");
    }

    #[test]
    fn a_tunnel_to_each_node_is_made_with_its_route_and_rule_and_read_back() {
        let mut f = Fake::default();
        let mut a = Agent::new(&mut f, "/k".into());
        let changes = a.apply(&state(&[(K1, "192.0.2.1:51820", &["10.240.0.4/32", "10.240.1.2/32"])])).unwrap();
        assert!(changes.iter().any(|c| matches!(c, Change::AddTunnel { name, .. } if name == "fdt-4")), "{changes:?}");
        let calls = f.calls.clone();
        let at = |c: &str| calls.iter().position(|x| x == c).unwrap_or_else(|| panic!("{c} not in {calls:#?}"));
        assert!(at("ip link add fdt-4 type ipip local 10.240.0.7 remote 10.240.0.4") < at("ip link set fdt-4 mtu 1400 up"));
        at("ip addr add 10.240.0.7/32 dev fdt-4");
        at("sysctl -qw net.ipv4.conf.fdt-4.rp_filter=2");
        assert!(at("ip route replace default dev fdt-4 table 64772") < at("ip rule add fwmark 0xfd04 lookup 64772 pref 1000"));
        at("ip -d -o link show type ipip");

        let shown = "4: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN\\    link/ipip 0.0.0.0 brd 0.0.0.0 promiscuity 0\n75: fdt-4@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1400 qdisc noqueue state UNKNOWN\\    link/ipip 10.240.0.7 peer 10.240.0.4 promiscuity 0 \\    ipip any remote 10.240.0.4 local 10.240.0.7 ttl inherit\n";
        assert_eq!(parse_tunnels(shown), [("fdt-4".to_string(), crate::plan::Tunnel { local: "10.240.0.7".into(), remote: "10.240.0.4".into(), mtu: 1400 })].into(), "only ours");

        let mut f = Fake { out: [("ip -d -o link show type ipip".to_string(), shown.to_string())].into(), ..Default::default() };
        let mut a = Agent::new(&mut f, "/k".into());
        a.apply(&state(&[])).unwrap();
        let calls = f.calls.clone();
        let at = |c: &str| calls.iter().position(|x| x == c).unwrap_or_else(|| panic!("{c} not in {calls:#?}"));
        assert!(at("ip rule del fwmark 0xfd04 lookup 64772") < at("ip link del fdt-4"), "its node gone: the rule, then the tunnel");
    }

    #[test]
    fn docker_lets_through_what_goes_by_a_tunnel_and_its_replies() {
        let mut f = Fake { fail: vec!["iptables -C DOCKER-USER -o fdt-+ -m conntrack --ctstate DNAT -j ACCEPT".into(), "iptables -C DOCKER-USER -i fdt-+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".into()], ..Default::default() };
        Agent::new(&mut f, "/k".into()).apply(&state(&[])).unwrap();
        assert!(f.calls.contains(&"iptables -I DOCKER-USER -o fdt-+ -m conntrack --ctstate DNAT -j ACCEPT".to_string()), "{:#?}", f.calls);
        assert!(f.calls.contains(&"iptables -I DOCKER-USER -i fdt-+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string()));
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

    #[test]
    fn a_floating_address_goes_on_its_own_interface_and_is_announced_on_its_lan_once() {
        let mut f = Fake { fail: vec!["ip -o link show dev fd-ext".into()], ..Default::default() };
        f.out.insert("ip -4 -o addr show".into(), LAN.into());
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&floating(&["192.0.2.10"])).unwrap();
        drop(a);
        let at = |c: &str| f.calls.iter().position(|x| x == c).unwrap_or_else(|| panic!("{c} not in {:#?}", f.calls));
        assert!(at("ip link add fd-ext type dummy") < at("ip link set fd-ext up"));
        assert!(at("ip addr add 192.0.2.10/32 dev fd-ext") < at("arping -U -c 2 -I eth0 192.0.2.10"), "on the interface whose network holds it");

        let mut f = Fake::default();
        f.out.insert("ip -4 -o addr show".into(), LAN.into());
        f.out.insert("ip -4 -o addr show dev fd-ext".into(), "9: fd-ext    inet 192.0.2.10/32 scope global fd-ext\\       valid_lft forever\n".into());
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&floating(&["192.0.2.10"])).unwrap();
        a.apply(&floating(&["192.0.2.10"])).unwrap();
        drop(a);
        assert!(!f.calls.iter().any(|c| c.starts_with("ip link add fd-ext") || c.starts_with("ip addr add 192.0.2.10")), "there already: {:#?}", f.calls);
        assert_eq!(f.calls.iter().filter(|c| c.starts_with("arping")).count(), 1, "announced once by this agent");
    }

    #[test]
    fn an_announcement_that_failed_is_tried_again_and_outside_a_lan_goes_by_the_default_route() {
        let mut f = Fake { fail: vec!["arping -U -c 2 -I eth1 198.51.100.7".into()], ..Default::default() };
        f.out.insert("ip -4 -o addr show".into(), LAN.into());
        f.out.insert("ip -4 route show default".into(), "default via 192.0.2.1 dev eth1 proto dhcp src 192.0.2.5 metric 100\n".into());
        let mut a = Agent::new(&mut f, "k".into());
        assert!(a.apply(&floating(&["198.51.100.7"])).is_err(), "the announcement failed: said so");
        assert!(a.apply(&floating(&["198.51.100.7"])).is_err());
        drop(a);
        assert_eq!(f.calls.iter().filter(|c| c.starts_with("arping")).count(), 2, "tried at the next state");
    }

    #[test]
    fn a_floating_address_given_away_is_taken_off_and_all_go_when_fenced() {
        let mut f = Fake::default();
        f.out.insert("ip -4 -o addr show".into(), LAN.into());
        f.out.insert("ip -4 -o addr show dev fd-ext".into(), "9: fd-ext    inet 192.0.2.10/32 scope global fd-ext\n9: fd-ext    inet 192.0.2.11/32 scope global fd-ext\n".into());
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&floating(&["192.0.2.10"])).unwrap();
        a.drop_floating().unwrap();
        drop(a);
        assert!(f.calls.contains(&"ip addr del 192.0.2.11/32 dev fd-ext".to_string()), "{:#?}", f.calls);
        assert!(!f.calls.contains(&"ip addr del 192.0.2.10/32 dev fd-ext".to_string()));
        assert_eq!(f.calls.last().unwrap(), "ip addr flush dev fd-ext");

        let mut f = Fake { fail: vec!["ip -o link show dev fd-ext".into()], ..Default::default() };
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&floating(&[])).unwrap();
        a.drop_floating().unwrap();
        drop(a);
        assert!(!f.calls.iter().any(|c| c.contains("fd-ext") && !c.starts_with("ip -o link show")), "none held, no interface made: {:#?}", f.calls);
    }

    #[test]
    fn a_floating_address_that_is_not_a_lan_s_refuses_the_state_whole() {
        for bad in ["10.240.1.5", "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "169.254.1.1", "192.0.2.10/24", "x"] {
            let mut f = Fake::default();
            assert!(Agent::new(&mut f, "k".into()).apply(&floating(&[bad])).is_err(), "{bad}");
            assert!(f.calls.is_empty(), "{bad}: nothing touched, {:#?}", f.calls);
        }
    }

    #[test]
    fn traffic_is_read_from_conntrack_with_accounting_switched_on_once() {
        let mut f = Fake::default();
        f.out.insert("conntrack -L -o extended,id".into(), "ipv4     2 tcp      6 431998 ESTABLISHED src=10.240.1.2 dst=10.240.1.9 sport=4 dport=80 packets=3 bytes=10 src=10.240.1.9 dst=10.240.1.2 sport=80 dport=4 packets=2 bytes=20 [ASSURED] mark=0 use=1 id=1\n".into());
        let mut a = Agent::new(&mut f, "k".into());
        a.apply(&state(&[(K1, "192.0.2.1:51820", &["10.240.1.9/32"])])).unwrap();
        let r = a.traffic().unwrap();
        assert_eq!((r.flows.len(), r.flows[0].dst.as_str(), r.flows[0].bytes_in), (1, "10.240.1.9", 20), "the peer's workload, known from the state");
        a.traffic().unwrap();
        drop(a);
        assert_eq!(f.calls.iter().filter(|c| c.starts_with("sysctl -qw net.netfilter.nf_conntrack_acct=1")).count(), 1, "{:#?}", f.calls);
        assert_eq!(f.calls.iter().filter(|c| *c == "conntrack -L -o extended,id").count(), 2);
    }
}

