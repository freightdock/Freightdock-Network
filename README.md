# freightdock-network

The network-agent of a Freightdock cluster: it will run on every worker and apply the network state the managers
decide (the mesh between workers, stable workload IPs, routes, external exposures), using established Linux
networking rather than a transport of its own.

Nothing here yet, on purpose: networking is plan phase 8 and 9, after the manager and worker can run, schedule, recover
and fence workloads. See Manager's [ROADMAP.md](https://github.com/freightdock/Manager/blob/main/ROADMAP.md). Its
contract will be a new file in Contracts (`network.proto`), and the choice of overlay (WireGuard, VXLAN, ...) is made
once the requirements in the plan's section 6.6 are written down.

GPL-3.0-only, as Freightdock.
