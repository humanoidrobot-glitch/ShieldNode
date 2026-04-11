//! Bidirectional TUN ↔ Sphinx packet forwarding loop.
//!
//! Outbound: TUN → Sphinx wrap (3 layers) → UDP to entry node.
//! Inbound:  UDP from entry node → peel 3 return-path layers → TUN.
//!
//! The return path uses per-hop layered encryption. Each relay node wraps one
//! layer using `encrypt(session_key, hop_index + RETURN_NONCE_OFFSET, payload)`.
//! The client peels layers in order: entry, relay, exit.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::aead;
use crate::circuit::CircuitState;
use crate::tun::ClientTun;

use shieldnode_types::aead::RETURN_NONCE_OFFSET;

/// Build a Sphinx-wrapped relay frame for an outbound IP packet.
///
/// Uses the circuit's pre-built Sphinx route. Wire format:
/// `[8-byte session_id BE][Sphinx packet bytes]`.
fn wrap_outbound(ip_packet: &[u8], circuit: &CircuitState) -> Result<Vec<u8>, String> {
    let route = circuit.build_sphinx_route();
    let sphinx = crate::sphinx::SphinxPacket::create(&route, ip_packet)?;
    let sphinx_bytes = sphinx.to_bytes();

    let session_id = circuit.entry.session_id;
    let mut frame = Vec::with_capacity(8 + sphinx_bytes.len());
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(&sphinx_bytes);

    Ok(frame)
}

/// Peel return-path encryption layers from an inbound packet.
///
/// Each relay node wraps one layer: exit encrypts first (outermost from
/// client's perspective is entry's layer). Client decrypts in order:
/// entry (nonce 0+OFFSET), relay (nonce 1+OFFSET), exit (nonce 2+OFFSET).
fn decrypt_inbound(
    payload: &[u8],
    circuit: &CircuitState,
) -> Result<Vec<u8>, String> {
    let layers = [
        (&circuit.entry.session_key, circuit.entry.hop_index + RETURN_NONCE_OFFSET),
        (&circuit.relay.session_key, circuit.relay.hop_index + RETURN_NONCE_OFFSET),
        (&circuit.exit.session_key, circuit.exit.hop_index + RETURN_NONCE_OFFSET),
    ];

    let mut current = payload.to_vec();
    for (key, nonce) in &layers {
        current = aead::decrypt(key, *nonce, &current)
            .map_err(|_| format!("return-path decrypt failed at nonce {nonce}"))?;
    }

    Ok(current)
}

/// Spawn the bidirectional TUN ↔ network forwarding loops.
///
/// Returns a `CancellationToken` that stops both loops when cancelled.
pub async fn spawn_tun_loops(
    tun: Arc<ClientTun>,
    circuit: CircuitState,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
) -> Result<CancellationToken, String> {
    let cancel = CancellationToken::new();

    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("failed to bind TUN loop socket: {e}"))?,
    );

    let entry_relay_addr: std::net::SocketAddr = {
        let ep: std::net::SocketAddr = circuit
            .entry
            .endpoint
            .parse()
            .map_err(|e| format!("invalid entry endpoint: {e}"))?;
        std::net::SocketAddr::new(ep.ip(), ep.port() + 1)
    };

    // ── Outbound: TUN → Sphinx → entry node ──────────────────────────
    {
        let tun = Arc::clone(&tun);
        let circuit = circuit.clone();
        let socket = Arc::clone(&socket);
        let cancel = cancel.clone();
        let bytes_sent = Arc::clone(&bytes_sent);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("TUN outbound loop stopped");
                        break;
                    }
                    result = tun.read_packet(&mut buf) => {
                        match result {
                            Ok(n) if n > 0 => {
                                match wrap_outbound(&buf[..n], &circuit) {
                                    Ok(frame) => {
                                        if let Err(e) = socket.send_to(&frame, entry_relay_addr).await {
                                            warn!(error = %e, "failed to send to entry node");
                                        } else {
                                            bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                        }
                                    }
                                    Err(e) => warn!(error = %e, "Sphinx wrap failed"),
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!(error = %e, "TUN read error");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Inbound: entry node → decrypt → TUN ─────────────────────────
    {
        let tun = Arc::clone(&tun);
        let cancel = cancel.clone();
        let bytes_received = Arc::clone(&bytes_received);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("TUN inbound loop stopped");
                        break;
                    }
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((n, from)) if n > 8 => {
                                // Validate sender is the entry node.
                                if from != entry_relay_addr {
                                    debug!(from = %from, expected = %entry_relay_addr, "ignoring packet from unknown source");
                                    continue;
                                }
                                // Strip 8-byte session_id framing.
                                let payload = &buf[8..n];
                                match decrypt_inbound(payload, &circuit) {
                                    Ok(ip_packet) if !ip_packet.is_empty() => {
                                        bytes_received.fetch_add(ip_packet.len() as u64, Ordering::Relaxed);
                                        if let Err(e) = tun.write_packet(&ip_packet).await {
                                            warn!(error = %e, "TUN write error");
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) => debug!(error = %e, "inbound decrypt failed"),
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!(error = %e, "relay socket recv error");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    Ok(cancel)
}
