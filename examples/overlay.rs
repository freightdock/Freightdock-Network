//! By hand on a node, as root, to try the agent without a cluster:
//!
//!   overlay key <file>                                  make or read the key, print its public half
//!   overlay apply <file> <subnet> [<key>=<host:port>=<addr,...> ...]   one stack's subnet, the other nodes
//!   overlay arp <bridge>                                proxy ARP on a stack's bridge
//!   overlay rules                                       the nftables ruleset of a sample state, for `nft -c -f -`

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
            let s = v1::NetworkState { version: 1, cluster_range: "10.240.0.0/16".into(), mtu: 1420, peers, stacks: vec![v1::StackNetwork { stack: "t".into(), subnet: a[2].clone(), gateway: String::new() }], node_address: String::new(), exposures: vec![], floating: vec![] };
            for c in apply::Agent::new(apply::System, a[1].clone().into()).apply(&s)? {
                println!("{c:?}");
            }
        }
        Some("rules") => {
            let ex = |port, targets: &[&str]| v1::Exposure { stack: "web".into(), protocol: "tcp".into(), port, targets: targets.iter().map(|t| t.to_string()).collect() };
            let s = v1::NetworkState {
                version: 1,
                cluster_range: "10.240.0.0/16".into(),
                mtu: 1420,
                peers: vec![],
                stacks: vec![v1::StackNetwork { stack: "web".into(), subnet: "10.240.1.0/24".into(), gateway: String::new() }, v1::StackNetwork { stack: "a-rather-long-stack-name".into(), subnet: "10.240.2.0/24".into(), gateway: String::new() }],
                node_address: "10.240.0.2".into(),
                exposures: vec![ex(8088, &["10.240.1.3:80", "10.240.1.4:80"]), ex(7453, &["10.240.1.5:7443"])],
                floating: vec![],
            };
            print!("{}", freightdock_network::plan::ruleset(&s)?);
        }
        Some("arp") => apply::Agent::new(apply::System, Default::default()).proxy_arp(&a[1])?,
        _ => anyhow::bail!("overlay key <file> | apply <file> <subnet> [<key>=<host:port>=<addrs>]... | arp <bridge>"),
    }
    Ok(())
}
