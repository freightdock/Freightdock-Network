# G9: internal networking, the design

The plan's section 6.3 to 6.6 asks for stable internal workload IPs, traffic between containers on different workers,
isolated stack networks, endpoints and routes that follow a workload when it moves, and state that recovers from the
managers; built on established Linux networking, no packet transport of our own, the technology picked only once the
requirements of 6.6 are written down. This is that write-up, and the choices that follow from it. Nothing here is built
until the owner has agreed to it.

## 6.6's requirements, answered

| Requirement | For the first release |
|---|---|
| Performance | Container to container across nodes at close to the link's speed for ordinary services (web, APIs, databases); no packet passes a manager. Kernel datapath only, nothing in user space per packet. |
| Topologies | Nodes in one or more subnets that reach each other over UDP. Nodes behind NAT that cannot be dialled are not supported yet. |
| Cross-subnet | Yes: the overlay runs over UDP between the nodes' addresses, routed like any other traffic. No multicast, no shared L2. |
| MTU | Overlay 1420 (1500 minus WireGuard's 80 for IPv6 underlays), set on the overlay and on every stack network, so containers never send what has to be fragmented. A cluster setting for underlays with a smaller MTU. |
| Encryption | Always on between nodes: the nodes' networks are not assumed to be trusted (Proxmox hosts, shared VLANs). |
| External routing | Not in G9 (G10): the internal network is not routed from outside; containers reach out through their node's NAT as today. |
| Gateway failover | Not in G9 (G10). G9 has no gateway: every node routes its own workloads' traffic. |

## The choice: a WireGuard mesh with routes per workload

Every node gets one WireGuard interface, `fd0`, with every other node as a peer (a full mesh: fine for tens of nodes,
which is this product's size). A WireGuard peer's `AllowedIPs` is a routing table bound to a key: a packet for an
address goes to the one peer that lists it, encrypted. So:

- **Stable IPs.** The managers give each workload an address from the cluster's range when it is placed (IPAM in the
  Raft state) and keep it for the workload's id. When the workload moves, its address moves from the old node's
  `AllowedIPs` to the new node's, and the routes follow. The address never changes, so nothing has to be told.
- **Cross-node traffic.** A container's packet for another node's workload goes host route `/32 dev fd0`, then
  WireGuard, then the other node's bridge. One encrypted hop, kernel only.
- **Encryption** comes with it; **cross-subnet** works because WireGuard is UDP between the node addresses.
- **Why not VXLAN**: unencrypted (it would need IPsec or WireGuard under it anyway), an L2 overlay with its flooding
  and forwarding tables to keep right, and in practice tied to one L2 segment or multicast. **Why not an existing CNI**
  (Flannel, Calico, Cilium): they expect Kubernetes, etcd or their own control plane; the managers are ours.

Each node's private key is made on the node and never leaves it; the worker reports the public key, and the managers
hand every node the others' keys, endpoints (the address its worker connects from, as `ui::target` reads it, at
51820/udp) and the addresses on them.

### Containers on the network

- **A network per stack.** Each stack gets a /24 of the cluster range (default range `10.240.0.0/16`, set when the
  cluster is made, never changed later), and on every node that runs a part of it a Docker bridge network
  `fd-<stack>` with that /24, gateway `.1`, MTU 1420. A workload runs on it with its fixed address (`--ip`).
- **Reaching a workload on another node.** The bridge's /24 says "on this link", so the node answers ARP for the
  remote workloads (proxy ARP on the bridge) and holds a `/32 dev fd0` route for each one: the kernel only answers
  for addresses routed elsewhere, so a local workload is never shadowed.
- **Isolation.** A stack's addresses talk only to that stack's addresses: nftables in the forward path (one table of
  our own, `freightdock`, never touching Docker's or the host's rules) drops traffic between two different stack
  /24s, on the bridges and on `fd0` alike.
- **Names.** A service's name resolves to its workloads' addresses: written into each container's hosts file when it
  is made (`extra_hosts`). Addresses are stable, so a move changes nothing; scaling a service rewrites the others at
  the next deploy. A DNS server of our own is left for when this is not enough.
- **The host's own network is untouched** (6.2): one interface `fd0`, the bridges Docker makes, routes inside the
  cluster range only, and our own nftables table (the filter above and the masquerade below).

### Found on the test cluster (Docker 29.0, 2026-11-12)

A hand-made overlay between two nodes, before any code: the WireGuard handshake came up at once, but nothing reached
the container. Docker drops, in the `raw` table, every packet for a container's address that arrives on another
interface ("direct routing" protection), and in `filter` everything into a bridge it did not publish. A stack network
is therefore made with `com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected` (neither rule) and
`enable_ip_masquerade=false` (Docker's masquerade would also rewrite traffic into `fd0`, hiding which stack sent it);
our own table masquerades what leaves the cluster range for anywhere but a stack bridge:
`ip saddr <range> ip daddr != <range> oifname != "fd-*" masquerade`. With that, a container on one node reached
nginx on the other by address, the far end saw the real source address, and both still reached the internet.

The agent's own run on two workers (`examples/overlay.rs`, the same day): `fd0` made, keyed and peered by `wg`, the routes
and the table put in place, a container on one node fetched nginx on the other at its fixed address with its own
source address, still reached the internet, and a container of another stack was dropped; a second run changed
nothing.

The agent drives the established tools rather than netlink, so what it does can be read and done by hand: `ip`,
`wg` (wireguard-tools, installed with the node) and `nft`.

## Where it runs

The network-agent is this repository's crate, `freightdock-network`, a library the worker links and runs: the worker
already holds the session with the managers, its identity and the node's Docker, so the network state comes down the
same stream as the commands and there is still one command per role (the owner's rule). It applies the desired state
(interface, peers, routes, bridges, nftables) and reports what it has, as the worker does with containers: a
reconcile, never a sequence of commands to replay.

## What the managers keep

- The cluster range (`ClusterCreated` grows a field; an older cluster gets the default at the first start).
- Per stack its /24, per workload its address: given out at placement, kept across moves and redeploys, released when
  the stack or the workload goes. Two workloads never share one, by construction in the state machine.
- Per node its WireGuard public key and port, from its report.

## The order of work

1. Contracts: the network part of the session (the node's key in its report; the desired network state down).
2. Manager: IPAM in the state, the per-node network state, the stack's workloads given their addresses.
3. Network: the agent (`ip`, `wg` and `nft`: interface, peers, routes, proxy ARP, the table), tested against a fake
   runner and by hand on two nodes; the Docker networks are the worker's.
4. Worker: runs the agent, starts workloads on the stack network with their address and hosts.
5. Test cluster: two stacks, a service calling another across nodes by name, a stack that cannot reach the other,
   a workload moved by recovery and reached at the same address.

## Not in G9

Exposing services from outside, external IPs and gateways (G10); nodes that cannot be dialled (NAT traversal or a
relay); IPv6 inside the overlay; a cluster DNS server; network policy finer than "a stack talks to itself".
