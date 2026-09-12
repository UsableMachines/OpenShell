// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Direct A-record queries against the configured nameservers.
//!
//! Fleet membership changes whenever a replica arrives or leaves, and the
//! whole point of re-resolving on an interval is to notice. `getaddrinfo`
//! sits behind whatever the platform caches — nscd, systemd-resolved, a musl
//! stub with its own ideas — so a lookup can return a view older than the
//! interval that asked for it, with nothing in the answer saying so. Asking
//! the nameserver directly makes the interval mean what it says.
//!
//! It does not make the answer fresh. The nameserver has its own cache and
//! the record TTL still bounds how stale a reply can be; this removes one
//! cache from the path, not the last one.
//!
//! Deliberately small: one question, no search list, no CNAME chasing. The
//! caller passes an absolute name for a headless Service, which answers with
//! A records directly.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// Resolver configuration, read fresh for each query.
///
/// Re-read rather than cached because a kubelet can rewrite it, and this is
/// one file read per interval per sandbox.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Per-exchange bound. Membership tolerates a missed round — the previous
/// view is kept — so waiting longer than this buys nothing.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// Refuse a reply larger than this rather than grow a buffer for it. A
/// headless Service answer is a list of A records; nothing legitimate here
/// approaches it.
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// The standard DNS port. Resolver configuration has no syntax for another
/// one, so every nameserver line means this.
const DNS_PORT: u16 = 53;

/// Nameservers to ask, in the order the configuration lists them.
///
/// Only `nameserver` lines are read. `search` and `ndots` are what the OS
/// resolver would use to complete a partial name, and the caller passes an
/// absolute one precisely so that none of it applies.
fn nameservers(resolv_conf: &str) -> Vec<SocketAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let line = line.split(['#', ';']).next().unwrap_or_default();
            let mut fields = line.split_whitespace();
            if fields.next() != Some("nameserver") {
                return None;
            }
            let address = IpAddr::from_str(fields.next()?).ok()?;
            Some(SocketAddr::new(address, DNS_PORT))
        })
        .collect()
}

/// Resolve `name` to its A records, asking each configured nameserver in turn.
///
/// An absolute name is required: without a search list to fall back on, a
/// partial one would simply not resolve.
///
/// A name that exists with no addresses is `Ok(vec![])` — a headless Service
/// with no ready endpoints, which is a real state and not a failure to ask.
///
/// NXDOMAIN is an error instead, even though some DNS servers answer an empty
/// headless Service that way too. The two cases are indistinguishable in the
/// reply, and they are not equally costly: reading a name nobody publishes as
/// an empty fleet leaves a misconfigured discovery name connecting to nothing,
/// silently and forever, while reading a briefly empty fleet as unaskable
/// costs a kept view that was about to be replaced anyway.
pub async fn resolve_a(name: &str) -> io::Result<Vec<IpAddr>> {
    let config = std::fs::read_to_string(RESOLV_CONF)?;
    let servers = nameservers(&config);
    if servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{RESOLV_CONF} lists no nameserver"),
        ));
    }
    resolve_a_via(&servers, name).await
}

/// The query itself, against an explicit server list.
async fn resolve_a_via(servers: &[SocketAddr], name: &str) -> io::Result<Vec<IpAddr>> {
    let question = Name::from_str(name)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
        .to_lowercase();

    let mut last_error = None;
    for server in servers {
        match exchange(*server, &question).await {
            Ok(addresses) => return Ok(addresses),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no nameserver answered")))
}

/// One question to one nameserver, over UDP, retried over TCP if truncated.
///
/// Truncation is not a corner here: a fleet's worth of A records outgrows a
/// 512-byte reply at a few dozen replicas, and a truncated answer read as a
/// whole one would silently shrink the fleet to whatever fitted.
async fn exchange(server: SocketAddr, name: &Name) -> io::Result<Vec<IpAddr>> {
    let query = Query::query(name.clone(), RecordType::A);
    let mut request = Message::query();
    let id = request.metadata.id;
    request.metadata.recursion_desired = true;
    request.queries.push(query.clone());
    let wire = request
        .to_vec()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    let reply = udp_exchange(server, &wire).await?;
    let message = parse(&reply, id, &query)?;
    let message = if message.metadata.truncation {
        let reply = tcp_exchange(server, &wire).await?;
        parse(&reply, id, &query)?
    } else {
        message
    };

    match message.metadata.response_code {
        ResponseCode::NoError => {}
        code => {
            return Err(io::Error::other(format!(
                "nameserver {server} answered {code}"
            )));
        }
    }

    Ok(message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(IpAddr::V4(address.0)),
            _ => None,
        })
        .collect())
}

/// Reject a reply that is not an answer to the question asked, so a late or
/// spoofed datagram cannot become fleet membership.
fn parse(reply: &[u8], id: u16, query: &Query) -> io::Result<Message> {
    if reply.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::other("DNS reply exceeded the size bound"));
    }
    let message =
        Message::from_vec(reply).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if message.metadata.id != id
        || message.metadata.message_type != MessageType::Response
        || message.metadata.op_code != OpCode::Query
        || message.queries.as_slice() != std::slice::from_ref(query)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nameserver answered a different question",
        ));
    }
    Ok(message)
}

async fn udp_exchange(server: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    timeout(EXCHANGE_TIMEOUT, socket.send(request))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;

    let mut reply = vec![0_u8; MAX_MESSAGE_BYTES];
    let received = timeout(EXCHANGE_TIMEOUT, socket.recv(&mut reply))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    reply.truncate(received);
    Ok(reply)
}

async fn tcp_exchange(server: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = timeout(EXCHANGE_TIMEOUT, TcpStream::connect(server))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;

    let length = u16::try_from(request.len())
        .map_err(|_| io::Error::other("DNS query too large for TCP"))?;
    timeout(EXCHANGE_TIMEOUT, async {
        stream.write_u16(length).await?;
        stream.write_all(request).await
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;

    let length = timeout(EXCHANGE_TIMEOUT, stream.read_u16())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?? as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(io::Error::other("DNS reply exceeded the size bound"));
    }
    let mut reply = vec![0_u8; length];
    timeout(EXCHANGE_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    #[test]
    fn reads_nameservers_in_order_ignoring_everything_else() {
        let config = "\
# generated by the kubelet
search sandbox.svc.cluster.local svc.cluster.local
nameserver 10.43.0.10
nameserver 10.43.0.11 ; a second one
options ndots:5
nameserver not-an-address
";
        assert_eq!(
            nameservers(config),
            vec![
                SocketAddr::from(([10, 43, 0, 10], 53)),
                SocketAddr::from(([10, 43, 0, 11], 53)),
            ],
            "only nameserver lines, in order, and an unparseable one is skipped"
        );
    }

    #[test]
    fn a_commented_out_nameserver_is_not_a_nameserver() {
        assert!(nameservers("#nameserver 10.43.0.10\n").is_empty());
    }

    /// Answer one query, with whatever this test wants in it.
    fn serve_once(
        socket: UdpSocket,
        build: impl FnOnce(&Message) -> Message + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; MAX_MESSAGE_BYTES];
            let (received, from) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..received]).unwrap();
            let reply = build(&request);
            socket
                .send_to(&reply.to_vec().unwrap(), from)
                .await
                .unwrap();
        })
    }

    fn answer(request: &Message, addresses: &[Ipv4Addr]) -> Message {
        let query = request.queries[0].clone();
        let mut reply = Message::query();
        reply.metadata.id = request.metadata.id;
        reply.metadata.message_type = MessageType::Response;
        reply.metadata.op_code = OpCode::Query;
        reply.queries.push(query.clone());
        for address in addresses {
            reply.answers.push(Record::from_rdata(
                query.name.clone(),
                30,
                RData::A(A(*address)),
            ));
        }
        reply
    }

    #[tokio::test]
    async fn resolves_the_a_records_the_nameserver_returns() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let answering = serve_once(socket, |request| {
            answer(
                request,
                &[Ipv4Addr::new(10, 42, 0, 5), Ipv4Addr::new(10, 42, 0, 7)],
            )
        });

        let addresses = resolve_a_via(&[server], "openshell-headless.sandbox.svc.cluster.local.")
            .await
            .unwrap();
        answering.await.unwrap();

        assert_eq!(
            addresses,
            vec![IpAddr::from([10, 42, 0, 5]), IpAddr::from([10, 42, 0, 7])]
        );
    }

    #[tokio::test]
    async fn a_name_nobody_publishes_is_not_an_empty_fleet() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let answering = serve_once(socket, |request| {
            let mut reply = answer(request, &[]);
            reply.metadata.response_code = ResponseCode::NXDomain;
            reply
        });

        let error = resolve_a_via(&[server], "gone.svc.cluster.local.")
            .await
            .expect_err("a name that does not exist must not read as nobody there");
        answering.await.unwrap();

        assert!(error.to_string().contains("Non-Existent Domain"));
    }

    /// The other shape of an empty headless Service: the name exists, and
    /// answers with no addresses. That one is nobody there.
    #[tokio::test]
    async fn a_name_that_answers_with_no_addresses_is_an_empty_fleet() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let answering = serve_once(socket, |request| answer(request, &[]));

        let addresses = resolve_a_via(&[server], "openshell-headless.sandbox.svc.cluster.local.")
            .await
            .unwrap();
        answering.await.unwrap();

        assert!(addresses.is_empty());
    }

    #[tokio::test]
    async fn a_reply_to_a_different_question_is_rejected() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let answering = serve_once(socket, |request| {
            let mut reply = answer(request, &[Ipv4Addr::new(10, 42, 0, 5)]);
            reply.metadata.id = request.metadata.id.wrapping_add(1);
            reply
        });

        let error = resolve_a_via(&[server], "openshell-headless.sandbox.svc.cluster.local.")
            .await
            .expect_err("a mismatched id must not become fleet membership");
        answering.await.unwrap();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn falls_through_to_the_next_nameserver() {
        // Nothing is listening on the first address: a port this process
        // bound and dropped is refused or silently dropped, and either way
        // the second server is the one that answers.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_address = dead.local_addr().unwrap();
        drop(dead);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let answering = serve_once(socket, |request| {
            answer(request, &[Ipv4Addr::new(10, 42, 0, 9)])
        });

        let addresses = resolve_a_via(
            &[dead_address, server],
            "openshell-headless.sandbox.svc.cluster.local.",
        )
        .await
        .unwrap();
        answering.await.unwrap();

        assert_eq!(addresses, vec![IpAddr::from([10, 42, 0, 9])]);
    }
}
