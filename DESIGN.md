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

On the cluster, with the worker running the agent: a client reached `api-1` and `api-2` by name on either node; a
service moved to the other node kept its address, and its peers reached it again about 5 s after it started there:
the time a container's stale ARP entry for the old, local address takes to fail before it asks again and the host
answers by proxy. So when a container leaves a node, the worker has the stack's containers still there forget its
address's MAC (`nsenter -t <pid> -n ip neigh flush to <addr>`, the established tools again): measured again, the
clients on the old node reached the moved service without a missed request.

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

# G10: external networking (agreed 2026-11-12: the mesh first, floating IPs next; the client's address across
# nodes later)

The plan (2.4, 4.5, 6.5) asks for exposures keyed by external IP, protocol and port, forwarded by the workers (or
designated gateways), never through a manager, the external IP stable when the workload moves, several workloads
sharing one IP on different ports, and the host's own network left alone.

Today a published port (`ports: ["8088:80"]`) is Docker's: it answers only on the node the workload runs on, so its
address moves with the workload. Two ways to make it stable, which fit together:

- **A port on every worker (a routing mesh).** A stack's published port answers on every worker's own address: our
  `table inet freightdock` DNATs `<any worker>:8088` to the workload's overlay address (`10.240.x.y:80`), wherever it
  runs, and spreads over the replicas (`numgen random mod N`). Nothing on the host's interfaces changes. A move
  changes one map element on each node. The external IP is any worker's, put behind DNS or a load balancer the
  administrator already has.
- **Floating external IPs (VIPs).** An address the administrator gives the cluster (from its LAN), held by one
  worker at a time, the gateway, chosen by the managers: added as a /32 on an interface of our own (`fd-ext`), with
  ARP answered on the LAN interface for that address only, and a gratuitous ARP when it moves. Its ports DNAT as
  above. It moves when its gateway is fenced (never while the old holder may still answer: the fencing guarantee
  again). Gateway redundancy beyond that is G12.

The client's address: a connection that comes in on the workload's own node keeps it. One forwarded to another node
must have its reply come back through the node it came in on, so it is masqueraded to that node's overlay side, and
the workload sees the node, not the client (as Swarm's routing mesh and Kubernetes' NodePort do by default). Keeping
it across nodes needs policy routing on the replies, left for later. Both are refused for ports the host uses
itself (22, the managers' 7450 to 7453, 51820).

### Found on the test cluster (2026-11-12)

By hand first, then built: Docker's FORWARD chain drops what comes in on the LAN interface and goes out `fd0` (it
accepts only its own bridges), so two rules in `DOCKER-USER`, the chain Docker keeps for its users, let the mesh's
connections and their replies through. The node needs an address on `fd0` for the masquerade (`10.240.0.<n>`, given
by the managers at enrolment), and the far node's stack filter must let replies (`ct state established`) and the
nodes' addresses through. With that: a port published by a workload on one node answered on both, the workload saw
the client's address when it came in on its own node and the forwarding node's otherwise, the host's own traffic to
its address worked, a port was spread over two replicas, and a port taken by another stack or kept by the host was
refused at deploy.

Since G10.2 Docker publishes nothing for a workload on the overlay: the mesh alone answers its ports, on its own node
too (the prerouting and output chains), so two replicas of a service may run on one node. A target whose node
reports it not running is taken out of the map until it runs again.

G10.3, built as above: a floating address is held through Raft (`FloatingHeld`, refused while its holder is neither
fenced nor gone), on `fd-ext` as a /32, and announced with `arping -U` on the interface whose network holds it. The
LAN interface answers ARP for it because Linux answers for any local address by default (`arp_ignore=0`); a node
that sets it otherwise answers for none. A holder the cluster starts to fence is sent no floating address, and a
worker that fences itself takes them off first, so between its own timers and the managers' presumption there is a
gap with nobody answering (about 50 s with the default timers on the test cluster), never one with two.

# G9.8: the live view of the traffic (agreed 2026-11-12: built from the flows)

The owner chose flows (who talks to whom) over node links or counters per workload. Each worker reads its
connection tracking at every heartbeat (`conntrack -L -o extended,id`, `nf_conntrack_acct` switched on by the agent)
and reports what moved since the last one, added up per ends and port (`traffic.rs`). A connection is counted by one
node only: the one it started on (a workload of the node to anywhere, the destination read from the reply side, so a
published port's real target), or the one it came in on (from outside, DNATed by the mesh to a workload, or routed to
a workload of the node). The second leg of a mesh forward comes from a node's address and is left out. A client
outside the cluster is not named (only "outside" and the port it came in on); a destination outside is "outside"
with its port. The managers turn the overlay addresses into workloads and nodes for the UI.

# G10.5: exposures on the pool (agreed 2026-11-13, the owner's words in short)

A floating address is a pool address, not a node's: a stack picks an address and a port from the pool for a service,
outside its Compose file, and two stacks may use the same port on two addresses ("it would really reduce scalability
if we could only use a port once"). The address and port follow the workloads wherever they run (the mesh). Ready-made
Compose files work unchanged.

What leaves the cluster is only what was meant to: an exposure (pool address, port, protocol to a service's container
port) answers on its address alone; a Compose file's `ports:` answers on the nodes' own addresses only, never on a
pool address (`fib daddr type local ip daddr != { <pool held here> }`); everything else is internal, reached by name
inside its stack, and says so in the UI. A port is unique per address and protocol, and a pool address in use cannot
be taken out of the pool.

