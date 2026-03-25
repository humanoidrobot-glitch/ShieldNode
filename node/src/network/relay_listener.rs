use std::net::SocketAddr;
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::crypto::sphinx::SphinxPacket;
use crate::metrics::bandwidth::BandwidthTracker;
use crate::tunnel::tun_device::TunDevice;

use super::hop_codec;
use super::receipts;
use super::relay::{RelayService, SessionState};

/// Minimum packet size: 8-byte session_id + at least 1 byte of payload.
const MIN_PACKET_SIZE: usize = 8 + 1;

/// Minimum size for a relay data packet (session_id != 0):
/// 8-byte session_id + at least 68 bytes for a serialized SphinxPacket
/// (32 next_hop + 32 mac + 4 payload_len).
const MIN_DATA_PACKET_SIZE: usize = 8 + 68;

/// Default relay port used when the next-hop encoding has port == 0.
const DEFAULT_RELAY_PORT: u16 = 51821;

// ── control message types ─────────────────────────────────────────────

const MSG_SESSION_SETUP: u8 = 0x01;
const MSG_SESSION_TEARDOWN: u8 = 0x02;
const MSG_RECEIPT_SIGN: u8 = 0x03;

/// Expected payload length for SESSION_SETUP after the message-type byte:
/// 8 (session_id) + 32 (session_key) + 8 (hop_index) = 48
const SESSION_SETUP_PAYLOAD_LEN: usize = 8 + 32 + 8;

/// Expected payload length for SESSION_TEARDOWN after the message-type byte:
/// 8 (session_id) = 8
const SESSION_TEARDOWN_PAYLOAD_LEN: usize = 8;

/// Expected payload length for RECEIPT_SIGN after the message-type byte:
/// 8 (session_id) + 8 (cumulative_bytes) + 8 (timestamp) + 65 (client_signature) = 89
const RECEIPT_SIGN_PAYLOAD_LEN: usize = 8 + 8 + 8 + 65;

// ── ACK bytes ─────────────────────────────────────────────────────────

const ACK_SUCCESS: u8 = 0x01;
const ACK_FAILURE: u8 = 0x00;

/// A dedicated UDP listener for multi-hop relay traffic.
///
/// Relay packets use a simple framing: `[8-byte session_id][SphinxPacket bytes]`.
/// Each node listens on a relay port (default 51821, one above the WireGuard port).
///
/// When `session_id == 0` the remaining bytes are interpreted as a **control
/// message** (session setup / teardown) rather than a Sphinx packet.
///
/// When a data packet arrives the listener:
/// 1. Parses the 8-byte session_id.
/// 2. Deserializes the SphinxPacket from the remaining bytes.
/// 3. Peels one onion layer via `RelayService::forward_packet()`.
/// 4. If the resulting next_hop is all zeros this is the exit node — the
///    payload is written to the TUN device.
/// 5. Otherwise the re-wrapped packet is forwarded to the next hop's relay
///    port with the new session_id.
pub struct RelayListener {
    socket: UdpSocket,
    relay_service: Arc<Mutex<RelayService>>,
    tun: Option<Arc<TunDevice>>,
    /// Kept for future direct bandwidth bookkeeping (e.g. per-relay-hop stats).
    #[allow(dead_code)]
    bandwidth: Arc<Mutex<BandwidthTracker>>,
    /// Operator's ECDSA signer for co-signing EIP-712 bandwidth receipts.
    operator_signer: Option<PrivateKeySigner>,
    /// Pre-computed EIP-712 domain separator for the SessionSettlement contract.
    domain_separator: Option<B256>,
}

impl RelayListener {
    /// Bind the relay listener to `0.0.0.0:<port>`.
    ///
    /// When `operator_signer`, `chain_id`, and `settlement_address` are
    /// provided the listener can co-sign EIP-712 bandwidth receipts in
    /// response to `RECEIPT_SIGN` (0x03) control messages.  All three are
    /// optional — if any is `None` receipt signing is disabled.
    pub async fn bind(
        port: u16,
        relay_service: Arc<Mutex<RelayService>>,
        tun: Option<Arc<TunDevice>>,
        bandwidth: Arc<Mutex<BandwidthTracker>>,
        operator_signer: Option<PrivateKeySigner>,
        chain_id: Option<u64>,
        settlement_address: Option<Address>,
    ) -> Result<Self> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding relay listener on {addr}"))?;
        info!(%addr, "relay UDP listener bound");

        // Pre-compute the domain separator when all EIP-712 params are available.
        let domain_separator = match (chain_id, settlement_address) {
            (Some(cid), Some(addr)) => {
                let ds = receipts::compute_domain_separator(cid, addr);
                info!(
                    chain_id = cid,
                    settlement = %addr,
                    "EIP-712 domain separator computed for receipt co-signing"
                );
                Some(ds)
            }
            _ => None,
        };

        Ok(Self {
            socket,
            relay_service,
            tun,
            bandwidth,
            operator_signer,
            domain_separator,
        })
    }

    /// Main receive loop — runs until the task is cancelled.
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        info!(has_tun = self.tun.is_some(), "relay listener running");

        loop {
            let (n, peer_addr) = self.socket.recv_from(&mut buf).await?;

            if n < MIN_PACKET_SIZE {
                debug!(
                    peer = %peer_addr,
                    bytes = n,
                    "relay packet too short, dropping"
                );
                continue;
            }

            let packet = &buf[..n];

            // Parse framing: [8-byte session_id][remaining bytes]
            let session_id =
                u64::from_be_bytes(packet[..8].try_into().expect("slice is exactly 8 bytes"));

            // ── control channel (session_id == 0) ─────────────────────
            if session_id == 0 {
                let response = self.handle_control_message(&packet[8..], peer_addr).await;
                if let Err(e) = self.socket.send_to(&response, peer_addr).await {
                    warn!(
                        peer = %peer_addr,
                        error = %e,
                        "failed to send control ACK"
                    );
                }
                continue;
            }

            // ── data channel ──────────────────────────────────────────

            if n < MIN_DATA_PACKET_SIZE {
                debug!(
                    peer = %peer_addr,
                    bytes = n,
                    "relay data packet too short, dropping"
                );
                continue;
            }

            let sphinx_bytes = &packet[8..];

            let sphinx_packet = match SphinxPacket::from_bytes(sphinx_bytes) {
                Ok(pkt) => pkt,
                Err(e) => {
                    warn!(
                        peer = %peer_addr,
                        session_id,
                        error = %e,
                        "failed to deserialize SphinxPacket"
                    );
                    continue;
                }
            };

            debug!(
                peer = %peer_addr,
                session_id,
                payload_len = sphinx_packet.payload.len(),
                "received relay packet"
            );

            // Peel one layer
            let (next_hop, inner_packet) = {
                let svc = self.relay_service.lock().await;
                match svc.forward_packet(session_id, &sphinx_packet).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!(
                            session_id,
                            error = %e,
                            "forward_packet failed"
                        );
                        continue;
                    }
                }
            };

            // Check if this is the exit (next_hop == all zeros)
            if hop_codec::is_exit_hop(&next_hop) {
                // Exit node: write decrypted payload to TUN
                if let Some(ref tun) = self.tun {
                    if let Err(e) = tun.write_packet(&inner_packet.payload).await {
                        warn!(
                            session_id,
                            error = %e,
                            "failed to write relay payload to TUN"
                        );
                    } else {
                        debug!(
                            session_id,
                            payload_len = inner_packet.payload.len(),
                            "exit: wrote relay payload to TUN"
                        );
                    }
                } else {
                    warn!(
                        session_id,
                        "exit relay packet arrived but no TUN device available"
                    );
                }
            } else {
                // Forward to next hop
                if let Err(e) = self
                    .forward_to_next_hop(&next_hop, session_id, &inner_packet)
                    .await
                {
                    warn!(
                        session_id,
                        error = %e,
                        "failed to forward to next hop"
                    );
                }
            }
        }
    }

    /// Parse and execute a control message received on session_id 0.
    ///
    /// Returns the response bytes to send back to the peer.  For most
    /// message types this is a single-byte ACK (`0x01` success / `0x00`
    /// failure).  For `RECEIPT_SIGN` the response is the 65-byte node
    /// signature on success, or a 1-byte `0x00` on failure.
    async fn handle_control_message(&self, data: &[u8], peer_addr: SocketAddr) -> Vec<u8> {
        if data.is_empty() {
            warn!(peer = %peer_addr, "control message has no type byte");
            return vec![ACK_FAILURE];
        }

        let msg_type = data[0];
        let payload = &data[1..];

        match msg_type {
            MSG_SESSION_SETUP => {
                if payload.len() < SESSION_SETUP_PAYLOAD_LEN {
                    warn!(
                        peer = %peer_addr,
                        expected = SESSION_SETUP_PAYLOAD_LEN,
                        got = payload.len(),
                        "SESSION_SETUP payload too short"
                    );
                    return vec![ACK_FAILURE];
                }

                let real_session_id = u64::from_be_bytes(
                    payload[..8].try_into().expect("slice is exactly 8 bytes"),
                );
                let mut session_key = [0u8; 32];
                session_key.copy_from_slice(&payload[8..40]);
                let hop_index = u64::from_le_bytes(
                    payload[40..48].try_into().expect("slice is exactly 8 bytes"),
                );

                let state = SessionState {
                    session_id: real_session_id,
                    session_key,
                    hop_index,
                };

                let accepted = {
                    let mut svc = self.relay_service.lock().await;
                    svc.add_session(state)
                };

                if accepted {
                    info!(
                        peer = %peer_addr,
                        session_id = real_session_id,
                        hop_index,
                        "SESSION_SETUP accepted"
                    );
                    vec![ACK_SUCCESS]
                } else {
                    warn!(
                        peer = %peer_addr,
                        session_id = real_session_id,
                        "SESSION_SETUP rejected (duplicate session_id)"
                    );
                    vec![ACK_FAILURE]
                }
            }

            MSG_SESSION_TEARDOWN => {
                if payload.len() < SESSION_TEARDOWN_PAYLOAD_LEN {
                    warn!(
                        peer = %peer_addr,
                        expected = SESSION_TEARDOWN_PAYLOAD_LEN,
                        got = payload.len(),
                        "SESSION_TEARDOWN payload too short"
                    );
                    return vec![ACK_FAILURE];
                }

                let target_session_id = u64::from_be_bytes(
                    payload[..8].try_into().expect("slice is exactly 8 bytes"),
                );

                {
                    let mut svc = self.relay_service.lock().await;
                    svc.remove_session(target_session_id);
                }

                info!(
                    peer = %peer_addr,
                    session_id = target_session_id,
                    "SESSION_TEARDOWN accepted"
                );
                vec![ACK_SUCCESS]
            }

            MSG_RECEIPT_SIGN => {
                self.handle_receipt_sign(payload, peer_addr).await
            }

            other => {
                warn!(
                    peer = %peer_addr,
                    msg_type = other,
                    "unknown control message type"
                );
                vec![ACK_FAILURE]
            }
        }
    }

    /// Handle a `RECEIPT_SIGN` (0x03) control message.
    ///
    /// Payload layout (89 bytes):
    /// ```text
    /// [8 bytes: session_id BE]
    /// [8 bytes: cumulative_bytes BE]
    /// [8 bytes: timestamp BE]
    /// [65 bytes: client_signature (r||s||v)]
    /// ```
    ///
    /// On success returns the 65-byte node co-signature.
    /// On failure returns a single `0x00` byte.
    async fn handle_receipt_sign(&self, payload: &[u8], peer_addr: SocketAddr) -> Vec<u8> {
        // ── validate prerequisites ───────────────────────────────────
        let (signer, domain_sep) = match (&self.operator_signer, &self.domain_separator) {
            (Some(s), Some(ds)) => (s, ds),
            _ => {
                warn!(
                    peer = %peer_addr,
                    "RECEIPT_SIGN received but receipt signing is not configured"
                );
                return vec![ACK_FAILURE];
            }
        };

        if payload.len() < RECEIPT_SIGN_PAYLOAD_LEN {
            warn!(
                peer = %peer_addr,
                expected = RECEIPT_SIGN_PAYLOAD_LEN,
                got = payload.len(),
                "RECEIPT_SIGN payload too short"
            );
            return vec![ACK_FAILURE];
        }

        // ── parse fields ─────────────────────────────────────────────
        let session_id =
            u64::from_be_bytes(payload[..8].try_into().expect("slice is exactly 8 bytes"));
        let cumulative_bytes =
            u64::from_be_bytes(payload[8..16].try_into().expect("slice is exactly 8 bytes"));
        let timestamp =
            u64::from_be_bytes(payload[16..24].try_into().expect("slice is exactly 8 bytes"));
        let _client_signature = &payload[24..89]; // 65 bytes, kept for future verification

        // ── verify session exists ────────────────────────────────────
        {
            let svc = self.relay_service.lock().await;
            if !svc.has_session(session_id) {
                warn!(
                    peer = %peer_addr,
                    session_id,
                    "RECEIPT_SIGN for unknown session"
                );
                return vec![ACK_FAILURE];
            }
        }

        // ── compute EIP-712 digest and sign ──────────────────────────
        let digest =
            receipts::compute_receipt_digest(domain_sep, session_id, cumulative_bytes, timestamp);

        match receipts::sign_receipt_digest(&digest, signer).await {
            Ok(sig) => {
                info!(
                    peer = %peer_addr,
                    session_id,
                    cumulative_bytes,
                    timestamp,
                    "RECEIPT_SIGN: co-signed receipt"
                );
                sig
            }
            Err(e) => {
                warn!(
                    peer = %peer_addr,
                    session_id,
                    error = %e,
                    "RECEIPT_SIGN: signing failed"
                );
                vec![ACK_FAILURE]
            }
        }
    }

    /// Serialize and send the inner packet to the next relay hop.
    ///
    /// The next_hop is decoded via [`hop_codec::decode_next_hop`] — the
    /// first 4 bytes are the IPv4 address, the next 2 bytes are the relay
    /// port (big-endian, with 0 falling back to the default relay port).
    async fn forward_to_next_hop(
        &self,
        next_hop: &[u8; 32],
        session_id: u64,
        inner_packet: &SphinxPacket,
    ) -> Result<()> {
        let (ip, port) = hop_codec::decode_next_hop(next_hop, DEFAULT_RELAY_PORT)
            .map_err(|e| anyhow::anyhow!(e))?;

        let dest = SocketAddr::from((ip, port));

        // Frame: [8-byte session_id][sphinx bytes]
        let sphinx_bytes = inner_packet.to_bytes();
        let mut frame = Vec::with_capacity(8 + sphinx_bytes.len());
        frame.extend_from_slice(&session_id.to_be_bytes());
        frame.extend_from_slice(&sphinx_bytes);

        self.socket
            .send_to(&frame, dest)
            .await
            .with_context(|| format!("sending relay packet to {dest}"))?;

        debug!(
            session_id,
            dest = %dest,
            frame_len = frame.len(),
            "forwarded relay packet to next hop"
        );

        Ok(())
    }
}
