//! By hand on a node, as root, to try the agent without a cluster:
//!
//!   overlay key <file>                                  make or read the key, print its public half
//!   overlay apply <file> <subnet> [<key>=<host:port>=<addr,...> ...]   one stack's subnet, the other nodes
//!   overlay arp <bridge>                                proxy ARP on a stack's bridge

use freightdock_network::{apply, key::Key};
use freightdock_proto::v1;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("key") => println!("{}", Key::load_or_make(a[1].as_ref())?.public()),
        Some("apply") => {
            Key::load_or_make(a[1].as_ref())?;
            let peers = a[3..]
                .iter()
                .map(|p| {
                    let mut f = p.splitn(3, '=');
                    let (k, e, ad) = (f.next().unwrap_or_default(), f.next().unwrap_or_default(), f.next().unwrap_or_default());
                    v1::NetworkPeer { node_id: String::new(), public_key: format!("{k}="), endpoint: e.into(), addresses: ad.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect() }
                })
                .collect();
            let s = v1::NetworkState { version: 1, cluster_range: "10.240.0.0/16".into(), mtu: 1420, peers, stacks: vec![v1::StackNetwork { stack: "t".into(), subnet: a[2].clone(), gateway: String::new() }] };
            for c in apply::Agent::new(apply::System, a[1].clone().into()).apply(&s)? {
                println!("{c:?}");
            }
        }
        Some("arp") => apply::Agent::new(apply::System, Default::default()).proxy_arp(&a[1])?,
        _ => anyhow::bail!("overlay key <file> | apply <file> <subnet> [<key>=<host:port>=<addrs>]... | arp <bridge>"),
    }
    Ok(())
}
