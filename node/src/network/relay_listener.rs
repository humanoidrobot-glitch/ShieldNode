use std::net::SocketAddr;
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::crypto::sphinx::SphinxPacket;
use crate::metrics::bandwidth::BandwidthTracker;
use crate::tunnel::packet_norm::{self, Denormalizer, NormalizedFrame, SequenceCounter, NORMALIZED_SIZE};
use crate::tunnel::tun_device::TunDevice;

use super::hop_codec;
use super::link_padding::LinkPaddingManager;
use super::nat_table::{self, NatTable};
use super::receipts;
use super::relay::{RelayService, SessionState};

use shieldnode_types::aead::{self as shared_aead, RETURN_NONCE_OFFSET};

/// Direction bit: MSB of session_id in wire framing.
/// 0 = forward (client → exit), 1 = return (exit → client).
const RETURN_DIRECTION_BIT: u64 = 0x8000_0000_0000_0000;

/// Minimum packet size: 8-byte session_id + at least 1 byte of payload.
const MIN_PACKET_SIZE: usize = 8 + 1;

/// Minimum size for a relay data packet (session_id != 0):
/// 8-byte session_id + at least 68 bytes for a serialized SphinxPacket
/// (32 next_hop + 32 mac + 4 payload_len).
const MIN_DATA_PACKET_SIZE: usize = 8 + 68;

/// Default relay port used when the next-hop encoding has port == 0.
const DEFAULT_RELAY_PORT: u16 = 51821;

// ── control message types (from shared registry) ──────────────────────

use super::control_msg::{self, RelayControlType, ACK_SUCCESS, ACK_FAILURE};

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
    socket: Arc<UdpSocket>,
    relay_service: Arc<RwLock<RelayService>>,
    tun: Option<Arc<TunDevice>>,
    /// Kept for future direct bandwidth bookkeeping (e.g. per-relay-hop stats).
    #[allow(dead_code)]
    bandwidth: Arc<Mutex<BandwidthTracker>>,
    /// Operator's ECDSA signer for co-signing EIP-712 bandwidth receipts.
    operator_signer: Option<PrivateKeySigner>,
    /// Pre-computed EIP-712 domain separator for the SessionSettlement contract.
    domain_separator: Option<B256>,
    /// Optional link padding manager, shared with the padding loop.
    link_padding: Option<Arc<Mutex<LinkPaddingManager>>>,
    /// Packet normalization: outgoing sequence counter (uncontended, single recv loop).
    norm_seq: std::sync::Mutex<SequenceCounter>,
    /// Packet normalization: incoming reassembly (uncontended, single recv loop).
    denorm: std::sync::Mutex<Denormalizer>,
    /// Optional batch reorder buffer. When present, forwarded packets are
    /// enqueued here instead of sent directly. The batch_flush_loop sends them.
    batch_buffer: Option<Arc<Mutex<super::batch_reorder::BatchBuffer>>>,
    /// NAT flow table for routing TUN responses to the correct session (exit mode only).
    nat_table: std::sync::Mutex<NatTable>,
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
        relay_service: Arc<RwLock<RelayService>>,
        tun: Option<Arc<TunDevice>>,
        bandwidth: Arc<Mutex<BandwidthTracker>>,
        operator_signer: Option<PrivateKeySigner>,
        chain_id: Option<u64>,
        settlement_address: Option<Address>,
        link_padding: Option<Arc<Mutex<LinkPaddingManager>>>,
        batch_buffer: Option<Arc<Mutex<super::batch_reorder::BatchBuffer>>>,
    ) -> Result<(Self, Arc<UdpSocket>)> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .with_context(|| format!("binding relay listener on {addr}"))?,
        );
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

        let socket_clone = socket.clone();

        Ok((
            Self {
                socket,
                relay_service,
                tun,
                bandwidth,
                operator_signer,
                domain_separator,
                link_padding,
                norm_seq: std::sync::Mutex::new(SequenceCounter::new()),
                denorm: std::sync::Mutex::new(Denormalizer::new()),
                batch_buffer,
                nat_table: std::sync::Mutex::new(NatTable::new()),
            },
            socket_clone,
        ))
    }

    /// Main receive loop — runs until the task is cancelled.
    ///
    /// Uses `tokio::select!` to handle both incoming relay packets AND
    /// TUN device responses (for the return path in exit mode).
    pub async fn run(&self) -> Result<()> {
        let mut udp_buf = vec![0u8; 65536];
        let mut tun_buf = vec![0u8; 65536];

        info!(has_tun = self.tun.is_some(), "relay listener running");

        loop {
            tokio::select! {
                // ── UDP relay packets (forward + return) ─────────────
                result = self.socket.recv_from(&mut udp_buf) => {
                    let (n, peer_addr) = result?;
                    self.handle_udp_packet(&udp_buf[..n], peer_addr).await;
                }

                // ── TUN responses (exit mode return path) ────────────
                result = async {
                    if let Some(ref tun) = self.tun {
                        tun.read_packet(&mut tun_buf).await
                    } else {
                        std::future::pending::<Result<usize, crate::tunnel::tun_device::TunError>>().await
                    }
                } => {
                    match result {
                        Ok(n) if n > 0 => {
                            self.handle_tun_response(&tun_buf[..n]).await;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(error = %e, "TUN read error in relay listener");
                        }
                    }
                }
            }
        }
    }

    /// Handle an incoming UDP packet (forward-path, return-path, or control).
    async fn handle_udp_packet(&self, raw: &[u8], peer_addr: SocketAddr) {
        if raw.len() < MIN_PACKET_SIZE {
            return;
        }

        // Denormalize if needed.
        let packet_data: Vec<u8> = if raw.len() == NORMALIZED_SIZE {
            let frame: [u8; NORMALIZED_SIZE] = raw.try_into().unwrap();
            let mut denorm = self.denorm.lock().expect("denorm lock");
            match denorm.denormalize(&frame) {
                Some(reassembled) => reassembled,
                None => return, // more fragments needed
            }
        } else {
            raw.to_vec()
        };

        if packet_data.len() < MIN_PACKET_SIZE {
            return;
        }

        let raw_session_id =
            u64::from_be_bytes(packet_data[..8].try_into().expect("8 bytes"));

        // ── control channel (session_id == 0) ─────────────────────
        if raw_session_id == 0 {
            let response = self.handle_control_message(&packet_data[8..], peer_addr).await;
            if let Err(e) = self.socket.send_to(&response, peer_addr).await {
                warn!(peer = %peer_addr, error = %e, "failed to send control ACK");
            }
            return;
        }

        // Check direction bit.
        let is_return = (raw_session_id & RETURN_DIRECTION_BIT) != 0;
        let session_id = raw_session_id & !RETURN_DIRECTION_BIT;

        if is_return {
            self.handle_return_packet(session_id, &packet_data[8..], peer_addr).await;
        } else {
            self.handle_forward_packet(session_id, &packet_data[8..], peer_addr).await;
        }
    }

    /// Handle a forward-path data packet: peel Sphinx layer, forward or write to TUN.
    async fn handle_forward_packet(&self, session_id: u64, sphinx_bytes: &[u8], peer_addr: SocketAddr) {
        if sphinx_bytes.len() < 68 {
            return;
        }

        let sphinx_packet = match SphinxPacket::from_bytes(sphinx_bytes) {
            Ok(pkt) => pkt,
            Err(e) => {
                warn!(session_id, error = %e, "failed to deserialize SphinxPacket");
                return;
            }
        };

        // Record prev_hop for return path routing.
        {
            let mut svc = self.relay_service.write().await;
            svc.set_prev_hop(session_id, peer_addr);
        }

        // Peel one layer.
        let (next_hop, inner_packet) = {
            let svc = self.relay_service.read().await;
            match svc.forward_packet(session_id, &sphinx_packet).await {
                Ok(result) => result,
                Err(e) => {
                    warn!(session_id, error = %e, "forward_packet failed");
                    return;
                }
            }
        };

        if hop_codec::is_exit_hop(&next_hop) {
            // Exit node: record NAT entry and write to TUN.
            if let Some(flow) = nat_table::extract_outbound_flow(&inner_packet.payload) {
                let mut nat = self.nat_table.lock().expect("nat_table lock");
                nat.insert(flow, session_id);
            }
            if let Some(ref tun) = self.tun {
                if let Err(e) = tun.write_packet(&inner_packet.payload).await {
                    warn!(session_id, error = %e, "failed to write to TUN");
                }
            }
        } else {
            if let Err(e) = self.forward_to_next_hop(&next_hop, session_id, &inner_packet).await {
                warn!(session_id, error = %e, "failed to forward to next hop");
            }
        }
    }

    /// Handle a return-path packet: wrap one encryption layer and forward to prev_hop.
    async fn handle_return_packet(&self, session_id: u64, payload: &[u8], _from: SocketAddr) {
        let (prev_hop, session_key, hop_index) = {
            let svc = self.relay_service.read().await;
            match svc.get_session(session_id) {
                Some(s) => match s.prev_hop {
                    Some(addr) => (addr, s.session_key, s.hop_index),
                    None => {
                        warn!(session_id, "return packet but no prev_hop recorded");
                        return;
                    }
                },
                None => {
                    debug!(session_id, "return packet for unknown session");
                    return;
                }
            }
        };

        let return_nonce = hop_index + RETURN_NONCE_OFFSET;
        let wrapped = match shared_aead::encrypt(&session_key, return_nonce, payload) {
            Ok(ct) => ct,
            Err(e) => {
                warn!(session_id, error = ?e, "return-path encrypt failed");
                return;
            }
        };

        let mut frame = Vec::with_capacity(8 + wrapped.len());
        frame.extend_from_slice(&(session_id | RETURN_DIRECTION_BIT).to_be_bytes());
        frame.extend_from_slice(&wrapped);

        if let Err(e) = self.socket.send_to(&frame, prev_hop).await {
            warn!(session_id, prev_hop = %prev_hop, error = %e, "failed to send return packet");
        }
    }

    /// Handle a TUN response: look up session via NAT table, wrap, and send back.
    async fn handle_tun_response(&self, ip_packet: &[u8]) {
        let flow = match nat_table::extract_inbound_flow(ip_packet) {
            Some(f) => f,
            None => return,
        };

        let session_id = {
            let nat = self.nat_table.lock().expect("nat_table lock");
            match nat.lookup(&flow) {
                Some(id) => id,
                None => {
                    debug!("TUN response has no NAT mapping, dropping");
                    return;
                }
            }
        };

        let (prev_hop, session_key, hop_index) = {
            let svc = self.relay_service.read().await;
            match svc.get_session(session_id) {
                Some(s) => match s.prev_hop {
                    Some(addr) => (addr, s.session_key, s.hop_index),
                    None => return,
                },
                None => return,
            }
        };

        // Encrypt with this hop's return-path nonce.
        let return_nonce = hop_index + RETURN_NONCE_OFFSET;
        let wrapped = match shared_aead::encrypt(&session_key, return_nonce, ip_packet) {
            Ok(ct) => ct,
            Err(_) => return,
        };

        let mut frame = Vec::with_capacity(8 + wrapped.len());
        frame.extend_from_slice(&(session_id | RETURN_DIRECTION_BIT).to_be_bytes());
        frame.extend_from_slice(&wrapped);

        if let Err(e) = self.socket.send_to(&frame, prev_hop).await {
            warn!(session_id, error = %e, "failed to send TUN return packet");
        } else {
            debug!(session_id, bytes = ip_packet.len(), "return: TUN → prev_hop");
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

        match RelayControlType::from_byte(msg_type) {
            Some(RelayControlType::SessionSetup) => {
                if payload.len() < control_msg::payload_len::SESSION_SETUP {
                    warn!(
                        peer = %peer_addr,
                        expected = control_msg::payload_len::SESSION_SETUP,
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
                    prev_hop: None,
                };

                let accepted = {
                    let mut svc = self.relay_service.write().await;
                    svc.add_session(state)
                };

                if accepted {
                    if let Some(ref lp) = self.link_padding {
                        lp.lock().await.add_peer(peer_addr);
                    }
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

            Some(RelayControlType::SessionTeardown) => {
                if payload.len() < control_msg::payload_len::SESSION_TEARDOWN {
                    warn!(
                        peer = %peer_addr,
                        expected = control_msg::payload_len::SESSION_TEARDOWN,
                        got = payload.len(),
                        "SESSION_TEARDOWN payload too short"
                    );
                    return vec![ACK_FAILURE];
                }

                let target_session_id = u64::from_be_bytes(
                    payload[..8].try_into().expect("slice is exactly 8 bytes"),
                );

                {
                    let mut svc = self.relay_service.write().await;
                    svc.remove_session(target_session_id);
                }

                if let Some(ref lp) = self.link_padding {
                    lp.lock().await.remove_peer(&peer_addr);
                }

                info!(
                    peer = %peer_addr,
                    session_id = target_session_id,
                    "SESSION_TEARDOWN accepted"
                );
                vec![ACK_SUCCESS]
            }

            Some(RelayControlType::ReceiptSign) => {
                self.handle_receipt_sign(payload, peer_addr).await
            }

            None => {
                warn!(
                    peer = %peer_addr,
                    msg_type,
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

        if payload.len() < control_msg::payload_len::RECEIPT_SIGN {
            warn!(
                peer = %peer_addr,
                expected = control_msg::payload_len::RECEIPT_SIGN,
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
            let svc = self.relay_service.read().await;
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

        // Build the raw frame: [8-byte session_id][sphinx bytes]
        let sphinx_bytes = inner_packet.to_bytes();
        let mut frame = Vec::with_capacity(8 + sphinx_bytes.len());
        frame.extend_from_slice(&session_id.to_be_bytes());
        frame.extend_from_slice(&sphinx_bytes);

        // Normalize to fixed-size frames (all wire packets become NORMALIZED_SIZE).
        let normalized = {
            let mut seq = self.norm_seq.lock().expect("norm_seq lock");
            packet_norm::normalize(&frame, &mut seq)
        };

        if let Some(ref bb) = self.batch_buffer {
            // Enqueue into batch buffer — batch_flush_loop sends after shuffling.
            let mut buf = bb.lock().await;
            for nf in &normalized {
                buf.enqueue(nf.data.to_vec(), dest);
            }
        } else {
            // Send directly (no batch reordering).
            for nf in &normalized {
                self.socket
                    .send_to(&nf.data, dest)
                    .await
                    .with_context(|| format!("sending normalized frame to {dest}"))?;
            }
        }

        debug!(
            session_id,
            dest = %dest,
            raw_len = frame.len(),
            frames = normalized.len(),
            batched = self.batch_buffer.is_some(),
            "forwarded relay packet to next hop"
        );

        Ok(())
    }
}
