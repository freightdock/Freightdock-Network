//! The network-agent of a Freightdock cluster (G9, `DESIGN.md`): a library the worker runs. It keeps the node's
//! WireGuard key ([`key`]) and makes the node's overlay what the managers' `NetworkState` says.

pub mod key;
pub mod plan;
