// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned `WireGuard` transport for one policy-authorized IPv4 endpoint.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use ipnet::IpNet;
use miette::Result;
use openshell_core::proto::{NetworkEndpoint, SandboxPolicy};
use openshell_core::provider_credentials::ProviderCredentialState;
use tokio_wireguard::config::{Config, Interface as InterfaceConfig, Peer};
use tokio_wireguard::interface::Interface;
use tokio_wireguard::x25519::{PublicKey, StaticSecret};

/// A single revision-scoped tunnel route. Its drop closes the userspace interface.
pub struct TunnelManager {
    id: String,
    destination: SocketAddrV4,
    accepted_generation: OnceLock<u64>,
    interface: tokio::sync::OnceCell<Interface>,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    endpoint: SocketAddrV4,
    local_address: tokio_wireguard::config::Address,
    route: IpNet,
    mtu: usize,
    keepalive: u16,
}

impl TunnelManager {
    pub(crate) fn owns_destination(&self, address: SocketAddr) -> bool {
        address == SocketAddr::V4(self.destination)
    }
    /// Validate the one-tunnel policy and start its supervisor-only UDP socket.
    pub(crate) fn new(
        policy: &SandboxPolicy,
        credentials: &ProviderCredentialState,
    ) -> Result<Option<Self>> {
        let single_port = |endpoint: &NetworkEndpoint| match endpoint.ports.as_slice() {
            [] if endpoint.port != 0 => Some(endpoint.port),
            [port] if endpoint.port == 0 || endpoint.port == *port => Some(*port),
            _ => None,
        };
        if policy.tunnels.is_empty() {
            if policy.network_policies.values().any(|rule| {
                rule.endpoints
                    .iter()
                    .any(|endpoint| !endpoint.tunnel_id.is_empty())
            }) {
                return Err(miette::miette!(
                    "tunneled endpoint has no tunnel configuration"
                ));
            }
            return Ok(None);
        }
        if policy.tunnels.len() != 1 {
            return Err(miette::miette!("phase 1 supports exactly one tunnel"));
        }
        let (id, tunnel) = policy.tunnels.iter().next().expect("one tunnel");
        if id.is_empty() {
            return Err(miette::miette!("tunnel name is empty"));
        }
        let endpoint_ip: Ipv4Addr = tunnel
            .endpoint_host
            .parse()
            .map_err(|_| miette::miette!("phase 1 requires an IPv4 appliance address"))?;
        let endpoint_port = u16::try_from(tunnel.endpoint_udp_port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| miette::miette!("invalid appliance UDP port"))?;
        let outer_allowed = policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
            .filter(|endpoint| {
                endpoint.protocol == "wireguard-udp"
                    && endpoint.host == tunnel.endpoint_host
                    && single_port(endpoint) == Some(u32::from(endpoint_port))
            })
            .count()
            == 1;
        if !outer_allowed {
            return Err(miette::miette!(
                "appliance UDP endpoint is not exactly authorized"
            ));
        }
        let inner: Vec<_> = policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
            .filter(|endpoint| !endpoint.tunnel_id.is_empty())
            .collect();
        if inner.len() != 1 || inner[0].tunnel_id != *id {
            return Err(miette::miette!(
                "phase 1 requires one inner endpoint bound to the tunnel"
            ));
        }
        let endpoint = inner[0];
        let inner_ip: Ipv4Addr = endpoint
            .host
            .parse()
            .map_err(|_| miette::miette!("phase 1 requires an IPv4 literal inner endpoint"))?;
        let inner_port = u16::try_from(single_port(endpoint).unwrap_or(0))
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| miette::miette!("invalid inner endpoint port"))?;
        if endpoint.allowed_ips != [inner_ip.to_string()] {
            return Err(miette::miette!(
                "inner endpoint must have one port and exact allowed IP"
            ));
        }
        if tunnel.allowed_inner_cidrs.len() != 1 {
            return Err(miette::miette!("phase 1 requires one inner CIDR"));
        }
        let route: IpNet = tunnel.allowed_inner_cidrs[0]
            .parse()
            .map_err(|_| miette::miette!("invalid inner tunnel CIDR"))?;
        if !matches!(route, IpNet::V4(_))
            || route.prefix_len() == 0
            || !route.contains(&std::net::IpAddr::V4(inner_ip))
        {
            return Err(miette::miette!("inner endpoint is outside tunnel route"));
        }
        let key_name = &tunnel.private_key_env_key;
        if !key_name.starts_with("OPENSHELL_WG_")
            || key_name.len() == "OPENSHELL_WG_".len()
            || !key_name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(miette::miette!("invalid tunnel private key reference"));
        }
        credentials.remove_env_key(key_name);
        let private_key = credentials
            .supervisor_tunnel_private_key(key_name)
            .ok_or_else(|| miette::miette!("tunnel key unavailable"))?;
        let decode = |value: &[u8]| -> Result<[u8; 32]> {
            value
                .try_into()
                .map_err(|_| miette::miette!("invalid WireGuard key length"))
        };
        let private = decode(
            &base64::engine::general_purpose::STANDARD
                .decode(private_key)
                .map_err(|_| miette::miette!("invalid WireGuard private key encoding"))?,
        )?;
        let public = decode(&tunnel.peer_public_key)?;
        let local_address = tunnel
            .local_address
            .parse()
            .map_err(|_| miette::miette!("invalid local tunnel address"))?;
        let mtu = if tunnel.mtu == 0 { 1280 } else { tunnel.mtu };
        if !(1200..=1420).contains(&mtu) {
            return Err(miette::miette!("tunnel MTU out of bounds"));
        }
        let keepalive = if tunnel.keepalive_seconds == 0 {
            25
        } else {
            tunnel.keepalive_seconds
        };
        if !(5..=120).contains(&keepalive) {
            return Err(miette::miette!("tunnel keepalive out of bounds"));
        }
        Ok(Some(Self {
            id: id.clone(),
            destination: SocketAddrV4::new(inner_ip, inner_port),
            accepted_generation: OnceLock::new(),
            interface: tokio::sync::OnceCell::new(),
            private_key: private,
            peer_public_key: public,
            endpoint: SocketAddrV4::new(endpoint_ip, endpoint_port),
            local_address,
            route,
            mtu: mtu as usize,
            keepalive: u16::try_from(keepalive).expect("validated keepalive bounds"),
        }))
    }

    /// Accept only the generation resulting from initial binary reconciliation.
    pub(crate) fn accept_initial_generation(&self, generation: u64) {
        let _ = self.accepted_generation.set(generation);
    }

    /// Connect only the destination pinned by the validated endpoint decision.
    pub(crate) async fn dial(
        &self,
        id: &str,
        destination: SocketAddr,
        policy_generation: u64,
    ) -> std::io::Result<tokio_wireguard::TcpStream> {
        if id != self.id
            || destination != SocketAddr::V4(self.destination)
            || self.accepted_generation.get() != Some(&policy_generation)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "tunnel route unavailable",
            ));
        }
        let interface = self
            .interface
            .get_or_try_init(|| async {
                Interface::new(Config {
                    interface: InterfaceConfig {
                        private_key: StaticSecret::from(self.private_key),
                        address: self.local_address,
                        listen_port: None,
                        mtu: Some(self.mtu),
                    },
                    peers: vec![Peer {
                        endpoint: Some(SocketAddr::V4(self.endpoint)),
                        allowed_ips: vec![self.route],
                        public_key: PublicKey::from(self.peer_public_key),
                        persistent_keepalive: Some(self.keepalive),
                    }],
                })
            })
            .await?;
        if interface.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "tunnel closed",
            ));
        }
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio_wireguard::TcpStream::connect(destination, interface),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel dial timed out"))?
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        if let Some(interface) = self.interface.get() {
            interface.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, NetworkTunnel};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn userspace_tunnel_connects_injects_and_fails_closed() {
        let (server_private, server_public) = tokio_wireguard::x25519::keypair();
        let (client_private, client_public) = tokio_wireguard::x25519::keypair();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        drop(udp);
        let server = Interface::new(Config {
            interface: InterfaceConfig {
                private_key: server_private,
                address: "10.80.0.2/32".parse().unwrap(),
                listen_port: Some(udp_port),
                mtu: Some(1280),
            },
            peers: vec![Peer {
                endpoint: None,
                allowed_ips: vec!["10.80.0.1/32".parse().unwrap()],
                public_key: client_public,
                persistent_keepalive: None,
            }],
        })
        .unwrap();
        let listener = tokio_wireguard::TcpListener::bind("10.80.0.2:8080", &server)
            .await
            .unwrap();
        let mut policy = SandboxPolicy::default();
        policy.tunnels.insert(
            "customer".into(),
            NetworkTunnel {
                endpoint_host: "127.0.0.1".into(),
                endpoint_udp_port: u32::from(udp_port),
                peer_public_key: server_public.as_bytes().to_vec(),
                private_key_env_key: "OPENSHELL_WG_PRIVATE_KEY".into(),
                local_address: "10.80.0.1/32".into(),
                allowed_inner_cidrs: vec!["10.80.0.2/32".into()],
                ..Default::default()
            },
        );
        policy.network_policies.insert(
            "outer".into(),
            NetworkPolicyRule {
                endpoints: vec![NetworkEndpoint {
                    host: "127.0.0.1".into(),
                    port: u32::from(udp_port),
                    ports: vec![u32::from(udp_port)],
                    protocol: "wireguard-udp".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        policy.network_policies.insert(
            "inner".into(),
            NetworkPolicyRule {
                endpoints: vec![NetworkEndpoint {
                    host: "10.80.0.2".into(),
                    port: 8080,
                    ports: vec![8080],
                    allowed_ips: vec!["10.80.0.2".into()],
                    tunnel_id: "customer".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let credentials = ProviderCredentialState::from_environment(
            1,
            HashMap::from([(
                "OPENSHELL_WG_PRIVATE_KEY".into(),
                base64::engine::general_purpose::STANDARD.encode(client_private.to_bytes()),
            )]),
            HashMap::new(),
            HashMap::new(),
        );
        let unrelated = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("API_TOKEN".into(), "must-stay-visible".into())]),
            HashMap::new(),
            HashMap::new(),
        );
        policy
            .tunnels
            .get_mut("customer")
            .unwrap()
            .private_key_env_key = "API_TOKEN".into();
        assert!(TunnelManager::new(&policy, &unrelated).is_err());
        assert!(unrelated.snapshot().child_env.contains_key("API_TOKEN"));
        policy
            .tunnels
            .get_mut("customer")
            .unwrap()
            .private_key_env_key = "OPENSHELL_WG_PRIVATE_KEY".into();
        let manager = TunnelManager::new(&policy, &credentials).unwrap().unwrap();
        assert!(crate::proxy::transparent_tunnel_route_refused(
            Some("customer"),
            &["10.80.0.2:8080".parse().unwrap()],
            Some(&manager),
        ));
        assert!(crate::proxy::transparent_tunnel_route_refused(
            None,
            &["10.80.0.2:8080".parse().unwrap()],
            Some(&manager),
        ));
        assert!(!crate::proxy::transparent_tunnel_route_refused(
            None,
            &["10.80.0.3:8080".parse().unwrap()],
            Some(&manager),
        ));
        assert!(
            !credentials
                .snapshot()
                .child_env
                .contains_key("OPENSHELL_WG_PRIVATE_KEY")
        );
        credentials.install_environment(
            2,
            HashMap::from([(
                "OPENSHELL_WG_PRIVATE_KEY".into(),
                base64::engine::general_purpose::STANDARD.encode(client_private.to_bytes()),
            )]),
            HashMap::new(),
            HashMap::new(),
        );
        assert!(
            !credentials
                .snapshot()
                .child_env
                .contains_key("OPENSHELL_WG_PRIVATE_KEY")
        );
        assert!(
            manager
                .dial("customer", "10.80.0.2:8080".parse().unwrap(), 1)
                .await
                .is_err()
        );
        manager.accept_initial_generation(42);
        assert!(
            manager
                .dial("wrong", "10.80.0.2:8080".parse().unwrap(), 42)
                .await
                .is_err()
        );
        assert!(
            manager
                .dial("customer", "10.80.0.2:8080".parse().unwrap(), 43)
                .await
                .is_err()
        );
        assert!(
            manager
                .dial("customer", "10.80.0.3:8080".parse().unwrap(), 42)
                .await
                .is_err()
        );
        let (client, accepted) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(15),
                manager.dial("customer", "10.80.0.2:8080".parse().unwrap(), 42),
            ),
            tokio::time::timeout(Duration::from_secs(15), listener.accept()),
        );
        let mut client = client.expect("WireGuard TCP connect timed out").unwrap();
        let (mut appliance, _) = accepted.expect("appliance accept timed out").unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut message = [0; 4];
        appliance.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"ping");
        let (_, resolver) = openshell_core::secrets::SecretResolver::from_provider_env(
            HashMap::from([("API_TOKEN".into(), "appliance-secret".into())]),
        );
        let raw = b"GET http://10.80.0.2:8080/p HTTP/1.1\r\nHost: 10.80.0.2:8080\r\nAuthorization: Bearer openshell:resolve:env:API_TOKEN\r\n\r\n";
        let rewritten = crate::proxy::rewrite_forward_request(
            raw,
            raw.len(),
            "/p",
            "10.80.0.2:8080",
            resolver.as_ref(),
            false,
        )
        .unwrap();
        client.write_all(&rewritten).await.unwrap();
        let mut observed = vec![0; rewritten.len()];
        appliance.read_exact(&mut observed).await.unwrap();
        assert!(
            String::from_utf8_lossy(&observed).contains("Authorization: Bearer appliance-secret")
        );
        assert!(!String::from_utf8_lossy(&observed).contains("openshell:resolve:env:"));
        drop(client);
        drop(appliance);
        drop(listener);
        server.close();
        tokio::time::timeout(Duration::from_secs(5), server.closed())
            .await
            .expect("server close timed out");
        // A selected tunnel route must never reach a direct listener, even
        // when that listener could accept an ordinary TCP connection.
        let direct_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct = direct_listener.local_addr().unwrap();
        let manager = Arc::new(manager);
        let dial = crate::proxy::TUNNEL_MANAGER.scope(Some(Arc::clone(&manager)), async {
            crate::proxy::dial_upstream(
                &None,
                "127.0.0.1",
                "127.0.0.1",
                direct.port(),
                &[direct],
                Some("customer"),
                42,
            )
            .await
        });
        assert!(
            dial.await.is_err(),
            "unrouted selected tunnel dial must fail"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), direct_listener.accept())
                .await
                .is_err(),
            "direct listener must observe no fallback connection"
        );

        let down_dial = crate::proxy::TUNNEL_MANAGER.scope(Some(manager), async {
            crate::proxy::dial_upstream(
                &None,
                "10.80.0.2",
                "10.80.0.2",
                8080,
                &["10.80.0.2:8080".parse().unwrap()],
                Some("customer"),
                42,
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(15), down_dial)
                .await
                .expect("down appliance dial must time out")
                .is_err(),
            "down appliance must refuse the selected tunnel dial"
        );
    }
}
