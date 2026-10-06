// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Userspace WireGuard test appliance for VPN-destination verification.
//!
//! Mirrors the in-process tunnel server pattern from `src/tunnel.rs` tests:
//! a `tokio_wireguard` Interface terminates the tunnel, and a
//! `tokio_wireguard::TcpListener` bound inside the tunnel address space
//! serves the inner destination.
//!
//! Sockets:
//!   - WireGuard UDP listener on 0.0.0.0:$WG_PORT (the tunnel endpoint).
//!   - Inner TCP service at $INNER_ADDR:8080, reachable only through the
//!     tunnel, answering "vpn-inner-ok".
//!   - Admin HTTP on 0.0.0.0:$ADMIN_PORT (plain host network, NOT through
//!     the tunnel): POST /peer {"public_key": "<base64 x25519>"} registers a
//!     sandbox supervisor peer; the appliance prints its own public key at
//!     startup so the destination request can carry it as peer_public_key.
//!
//! Peers are rebuilt on each /peer POST (the destination flow provisions the
//! supervisor key pair only at activation time, so the appliance cannot know
//! the client key until then). Per-sandbox keys at test scale: each /peer POST
//! adds one client public key.
//!
//! Build (from repo root, linux/arm64):
//!   cargo zigbuild --release --example vpn-appliance \
//!     -p openshell-supervisor-network --target aarch64-unknown-linux-gnu.2.28

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_wireguard::config::{Config, Interface as InterfaceConfig, Peer};
use tokio_wireguard::interface::Interface;
use tokio_wireguard::x25519::{PublicKey, StaticSecret};
const DEFAULT_WG_PORT: u16 = 51820;
const DEFAULT_ADMIN_PORT: u16 = 8081;
const INNER_TCP_PORT: u16 = 8080;

struct Appliance {
    server_secret: StaticSecret,
    server_public: PublicKey,
    wg_port: u16,
    inner_addr: String,
    /// Peer public keys (base64), one per registered sandbox supervisor.
    peers: Mutex<Vec<PublicKey>>,
    /// The live tunnel interface; rebuilt when a peer is added.
    interface: Mutex<Option<Interface>>,
}

fn b64_encode(bytes: &[u8]) -> String {
    // Minimal standard base64 (no dependency on a base64 crate here).
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(input: &str) -> Option<[u8; 32]> {
    let input: String = input.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let v = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    let arr: [u8; 32] = out.try_into().ok()?;
    Some(arr)
}

impl Appliance {
    fn new(server_secret: StaticSecret, wg_port: u16, inner_prefix: &str) -> Self {
        let server_public = PublicKey::from(&server_secret);
        Self {
            server_public,
            server_secret,
            wg_port,
            inner_addr: format!("{inner_prefix}.2"),
            peers: Mutex::new(Vec::new()),
            interface: Mutex::new(None),
        }
    }

    fn build_interface(&self, peers: &[PublicKey]) -> std::io::Result<Interface> {
        let client_allowed: std::net::IpAddr = format!("{}.1", self.inner_addr.rsplit_once('.').map(|(p, _)| p).unwrap_or("10.80.0"))
            .parse()
            .expect("client address");
        let peers = peers
            .iter()
            .map(|public| Peer {
                endpoint: None,
                allowed_ips: vec![format!("{}/32", client_allowed).parse().expect("client allowed_ips net")],
                public_key: *public,
                persistent_keepalive: None,
            })
            .collect();
        Interface::new(Config {
            interface: InterfaceConfig {
                private_key: self.server_secret.clone(),
                address: format!("{}/32", self.inner_addr).parse().expect("inner addr"),
                listen_port: Some(self.wg_port),
                mtu: Some(1280),
            },
            peers,
        })
    }

    async fn rebuild(&self) -> std::io::Result<()> {
        // Both the old and the new interface bind the same UDP port, so close
        // the old one before constructing its replacement.
        if let Some(old) = self.interface.lock().await.take() {
            old.close();
        }
        let peers = self.peers.lock().await.clone();
        let interface = self.build_interface(&peers)?;
        *self.interface.lock().await = Some(interface.clone());
        // Serve the inner destination bound inside the tunnel.
        let bind_addr: SocketAddr = format!("{}:{}", self.inner_addr, INNER_TCP_PORT)
            .parse()
            .expect("inner bind addr");
        let listener = tokio_wireguard::TcpListener::bind(bind_addr, &interface).await?;
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let _ = stream.write_all(b"vpn-inner-ok\n").await;
                            let mut buf = [0u8; 64];
                            let _ = stream.read(&mut buf).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let wg_port: u16 = std::env::var("WG_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_WG_PORT);
    let admin_port: u16 = std::env::var("ADMIN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_PORT);
    let inner_prefix =
        std::env::var("INNER_PREFIX").unwrap_or_else(|_| "10.80.0".to_string());

    let (server_secret, _server_public) = tokio_wireguard::x25519::keypair();
    let appliance = Arc::new(Appliance::new(server_secret, wg_port, &inner_prefix));
    appliance.rebuild().await.expect("initial tunnel interface");

    println!(
        "VPN_APPLIANCE_READY wg_port={wg_port} inner={} peer_public_key={}",
        format!("{}:{}", appliance.inner_addr, INNER_TCP_PORT),
        b64_encode(appliance.server_public.as_bytes())
    );

    // Minimal admin HTTP: POST /peer {"public_key": "..."} adds a client peer.
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", admin_port))
        .await
        .expect("admin bind");
    println!("VPN_APPLIANCE_ADMIN admin_port={admin_port}");
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("admin accept error: {e}");
                continue;
            }
        };
        let appliance = appliance.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            // crude body: everything after the blank line
                            let text = String::from_utf8_lossy(&buf);
                            let body = text
                                .split("\r\n\r\n")
                                .nth(1)
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            let (status, payload) = if body.contains("\"public_key\"") {
                                let key = body
                                    .split("\"public_key\"")
                                    .nth(1)
                                    .and_then(|rest| {
                                        rest.split('"').nth(1).map(str::to_string)
                                    })
                                    .unwrap_or_default();
                                match b64_decode(&key) {
                                    Some(raw) => {
                                        appliance
                                            .peers
                                            .lock()
                                            .await
                                            .push(PublicKey::from(raw));
                                        match appliance.rebuild().await {
                                            Ok(()) => (
                                                "200 OK",
                                                format!(
                                                    "{{\"peer_added\":true,\"peers\":{}}}",
                                                    appliance.peers.lock().await.len()
                                                ),
                                            ),
                                            Err(e) => (
                                                "500 Internal Server Error",
                                                format!("{{\"error\":\"{e}\"}}"),
                                            ),
                                        }
                                    }
                                    None => (
                                        "400 Bad Request",
                                        "{\"error\":\"invalid_base64\"}".to_string(),
                                    ),
                                }
                            } else {
                                ("400 Bad Request", "{\"error\":\"public_key required\"}".to_string())
                            };
                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                                payload.len()
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            break;
                        }
                        if buf.len() > 64 * 1024 {
                            break;
                        }
                    }
                }
            }
        });
    }
}
