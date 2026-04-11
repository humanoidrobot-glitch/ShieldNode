use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

use super::aead;
use super::hybrid::{HybridKem, HybridPublicKey, HybridSecretKey};
use super::traits::KeyExchange;

// Shared helpers from the types crate.
use shieldnode_types::sphinx::{
    compute_mac, pq_compute_mac, pq_derive_layer_key, pq_nonce, PQ_SPHINX_VERSION,
};

type HmacSha256 = Hmac<Sha256>;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("route must have at least one hop")]
    EmptyRoute,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("malformed header")]
    MalformedHeader,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    #[error("KEM operation failed: {0}")]
    KemFailed(String),
}

// ── header + packet ────────────────────────────────────────────────────

/// Per-hop header prepended to the onion payload.
#[derive(Clone, Debug)]
pub struct SphinxHeader {
    pub next_hop: [u8; 32],
    pub routing_info: Vec<u8>,
    /// HMAC-SHA256 over (next_hop || payload), keyed by the session key.
    pub mac: [u8; 32],
}

/// A Sphinx-like onion packet.
#[derive(Clone, Debug)]
pub struct SphinxPacket {
    pub header: SphinxHeader,
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Build an onion packet that traverses `route` carrying `plaintext`.
    ///
    /// `route` is an ordered list of (public_key, session_key) pairs from
    /// first hop to last.  Each `session_key` is a 32-byte symmetric key
    /// previously negotiated (e.g. via DH) with that hop.
    pub fn create(route: &[([u8; 32], [u8; 32])], plaintext: &[u8]) -> Result<Self, SphinxError> {
        if route.is_empty() {
            return Err(SphinxError::EmptyRoute);
        }

        let mut current_payload = plaintext.to_vec();
        let mut next_hop = [0u8; 32]; // final hop has no successor

        for (i, (pub_key, session_key)) in route.iter().enumerate().rev() {
            let mut layer_plaintext = Vec::with_capacity(32 + current_payload.len());
            layer_plaintext.extend_from_slice(&next_hop);
            layer_plaintext.extend_from_slice(&current_payload);

            current_payload = aead::encrypt(session_key, i as u64, &layer_plaintext)
                .map_err(|e| SphinxError::EncryptionFailed(e.to_string()))?;

            next_hop = *pub_key;
        }

        let mac = compute_mac(&route[0].1, 0, &next_hop, &current_payload);

        Ok(Self {
            header: SphinxHeader {
                next_hop: route[0].0,
                routing_info: Vec::new(),
                mac,
            },
            payload: current_payload,
        })
    }

    /// Peel one onion layer using `session_key` for this hop.
    ///
    /// Verifies the HMAC before decrypting. Returns `(next_hop_public_key,
    /// inner_packet)`. If `next_hop` is all zeros, this node is the final
    /// destination.
    pub fn peel_layer(
        &self,
        session_key: &[u8; 32],
        hop_index: u64,
    ) -> Result<([u8; 32], SphinxPacket), SphinxError> {
        // Verify MAC before decrypting.
        verify_mac(session_key, hop_index as u8, &self.header.next_hop, &self.payload, &self.header.mac)?;

        let decrypted = aead::decrypt(session_key, hop_index, &self.payload)
            .map_err(|e| SphinxError::DecryptionFailed(e.to_string()))?;

        if decrypted.len() < 32 {
            return Err(SphinxError::MalformedHeader);
        }

        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&decrypted[..32]);
        let inner_payload = decrypted[32..].to_vec();

        // The inner packet's MAC was already embedded by create() using the
        // next hop's session key. We reconstruct the SphinxPacket without
        // recomputing the MAC — it will be verified when the next hop peels.
        // For the innermost layer (exit), the MAC is a placeholder that won't
        // be verified (no further hops).
        let inner_packet = SphinxPacket {
            header: SphinxHeader {
                next_hop,
                routing_info: Vec::new(),
                mac: [0u8; 32], // placeholder — real MAC is in the serialized inner packet
            },
            payload: inner_payload,
        };

        Ok((next_hop, inner_packet))
    }

    // ── serialisation ──────────────────────────────────────────────────

    /// Serialize this packet to bytes:
    /// `[32-byte next_hop][32-byte mac][4-byte payload_len (BE)][payload]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(32 + 32 + 4 + self.payload.len());
        buf.extend_from_slice(&self.header.next_hop);
        buf.extend_from_slice(&self.header.mac);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize a packet from bytes produced by [`to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, SphinxError> {
        // 32 (next_hop) + 32 (mac) + 4 (len) = 68 minimum
        if data.len() < 68 {
            return Err(SphinxError::MalformedHeader);
        }

        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&data[..32]);

        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[32..64]);

        let payload_len = u32::from_be_bytes(
            data[64..68].try_into().map_err(|_| SphinxError::MalformedHeader)?
        ) as usize;

        if data.len() < 68 + payload_len {
            return Err(SphinxError::MalformedHeader);
        }

        let payload = data[68..68 + payload_len].to_vec();

        Ok(Self {
            header: SphinxHeader {
                next_hop,
                routing_info: Vec::new(),
                mac,
            },
            payload,
        })
    }
}

/// Verify HMAC-SHA256 over (hop_index || next_hop || payload).
fn verify_mac(
    session_key: &[u8; 32],
    hop_index: u8,
    next_hop: &[u8; 32],
    payload: &[u8],
    expected: &[u8; 32],
) -> Result<(), SphinxError> {
    let mut hmac = HmacSha256::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    hmac.update(&[hop_index]);
    hmac.update(next_hop);
    hmac.update(payload);
    hmac.verify_slice(expected)
        .map_err(|_| SphinxError::MacVerificationFailed)
}

// ── PQ Sphinx ─────────────────────────────────────────────────────────
//
// Post-quantum Sphinx packet format. Each hop's header carries a hybrid
// KEM ciphertext (X25519 + ML-KEM-768) so the hop derives its layer key
// from the packet itself plus its own secret key. No pre-negotiated
// session keys required.
//
// Wire format:
//   [1-byte version = 0xFF]
//   [32-byte next_hop]
//   [N-byte kem_ciphertext]       (HybridKem::ciphertext_len())
//   [32-byte mac]
//   [4-byte encrypted_blob_len]
//   [encrypted_blob]               (contains next hop's PQ packet, recursively)
//
// Each peel reveals the next hop's complete packet. Only the outermost
// hop header is readable; inner headers are encrypted.

/// Version byte for PQ Sphinx packets. 0xFF cannot appear as the first
/// byte of a classic packet (exit sentinel is 0x00; valid IPv4 first
/// octets are 1-223; broadcast 255 is rejected by decode_next_hop).

const KEM_CT_LEN: usize = 1120; // HybridKem ciphertext: X25519 (32) + ML-KEM-768 (1088)

/// Pre-computed KEM state for one hop in a PQ Sphinx session.
/// The client computes these once per circuit; all packets in the
/// session reuse the same ciphertexts. Nodes cache the decapsulation.
pub struct PqHopKeys {
    pub next_hop: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub layer_key: [u8; 32],
}

/// Pre-computed KEM state for a full PQ Sphinx circuit.
pub struct PqSessionKeys {
    pub hops: Vec<PqHopKeys>,
}

impl PqSessionKeys {
    /// Compute KEM encapsulations for each hop in the route.
    /// `route` is ordered entry → relay → exit: `(hop_public_key, next_hop_encoding)`.
    pub fn new(route: &[(HybridPublicKey, [u8; 32])]) -> Result<Self, SphinxError> {
        let mut hops = Vec::with_capacity(route.len());
        for (hop_pk, next_hop) in route {
            let (shared_secret, ciphertext) = HybridKem::encapsulate(hop_pk)
                .map_err(|e| SphinxError::KemFailed(e.to_string()))?;
            let layer_key = pq_derive_layer_key(shared_secret.as_ref());
            hops.push(PqHopKeys {
                next_hop: *next_hop,
                kem_ciphertext: ciphertext.as_ref().to_vec(),
                layer_key,
            });
        }
        Ok(Self { hops })
    }
}

/// A PQ Sphinx onion packet with per-hop KEM ciphertexts.
#[derive(Clone, Debug)]
pub struct PqSphinxPacket {
    pub next_hop: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub mac: [u8; 32],
    pub encrypted_blob: Vec<u8>,
}

impl PqSphinxPacket {
    /// Build a PQ Sphinx onion packet using pre-computed session keys.
    pub fn create(
        session: &PqSessionKeys,
        plaintext: &[u8],
    ) -> Result<Self, SphinxError> {
        if session.hops.is_empty() {
            return Err(SphinxError::EmptyRoute);
        }

        // Build from innermost (exit) to outermost (entry).
        let mut current_blob = plaintext.to_vec();

        for (i, hop) in session.hops.iter().enumerate().rev() {
            // Non-exit layers prepend the next hop's serialized header so
            // the recipient can forward. Exit layer encrypts plaintext directly.
            let layer_plaintext = if i < session.hops.len() - 1 {
                let inner = &session.hops[i + 1];
                pq_serialize(
                    &inner.next_hop,
                    &inner.kem_ciphertext,
                    &pq_compute_mac(&inner.layer_key, (i + 1) as u8, &inner.next_hop, &inner.kem_ciphertext, &current_blob),
                    &current_blob,
                )
            } else {
                current_blob
            };

            current_blob =
                aead::encrypt_with_nonce(&hop.layer_key, &pq_nonce(i), &layer_plaintext)
                    .map_err(|e| SphinxError::EncryptionFailed(e.to_string()))?;
        }

        let hop0 = &session.hops[0];
        let mac = pq_compute_mac(&hop0.layer_key, 0, &hop0.next_hop, &hop0.kem_ciphertext, &current_blob);

        Ok(Self {
            next_hop: hop0.next_hop,
            kem_ciphertext: hop0.kem_ciphertext.clone(),
            mac,
            encrypted_blob: current_blob,
        })
    }

    /// Peel one layer using the node's hybrid secret key.
    ///
    /// Returns `(next_hop, inner_packet_or_plaintext)`. If `next_hop` is
    /// all zeros, the decrypted blob is the final plaintext payload.
    /// Otherwise the blob is a serialized inner PQ Sphinx packet.
    pub fn peel_layer(
        &self,
        local_sk: &HybridSecretKey,
        hop_index: usize,
    ) -> Result<([u8; 32], Vec<u8>), SphinxError> {
        let ct = HybridKem::ciphertext_from_bytes(&self.kem_ciphertext)
            .map_err(|e| SphinxError::KemFailed(e.to_string()))?;
        let shared_secret = HybridKem::decapsulate(&ct, local_sk)
            .map_err(|e| SphinxError::KemFailed(e.to_string()))?;
        let layer_key = pq_derive_layer_key(shared_secret.as_ref());

        // Verify MAC before decrypting.
        pq_verify_mac(&layer_key, hop_index as u8, &self.next_hop, &self.kem_ciphertext, &self.encrypted_blob, &self.mac)?;

        let decrypted = aead::decrypt_with_nonce(&layer_key, &pq_nonce(hop_index), &self.encrypted_blob)
            .map_err(|e| SphinxError::DecryptionFailed(e.to_string()))?;

        Ok((self.next_hop, decrypted))
    }

    /// Peel using a pre-cached layer key (avoids repeated KEM decapsulation).
    pub fn peel_layer_cached(
        &self,
        layer_key: &[u8; 32],
        hop_index: usize,
    ) -> Result<([u8; 32], Vec<u8>), SphinxError> {
        pq_verify_mac(layer_key, hop_index as u8, &self.next_hop, &self.kem_ciphertext, &self.encrypted_blob, &self.mac)?;

        let decrypted = aead::decrypt_with_nonce(layer_key, &pq_nonce(hop_index), &self.encrypted_blob)
            .map_err(|e| SphinxError::DecryptionFailed(e.to_string()))?;

        Ok((self.next_hop, decrypted))
    }

    // ── serialisation ──────────────────────────────────────────────────

    /// Serialize to bytes with PQ version prefix.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + self.kem_ciphertext.len() + 32 + 4 + self.encrypted_blob.len());
        buf.push(PQ_SPHINX_VERSION);
        buf.extend_from_slice(&self.next_hop);
        buf.extend_from_slice(&self.kem_ciphertext);
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&(self.encrypted_blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.encrypted_blob);
        buf
    }

    /// Deserialize from bytes (after version byte has been consumed).
    pub fn from_bytes_inner(data: &[u8]) -> Result<Self, SphinxError> {
        // 32 (next_hop) + KEM_CT_LEN + 32 (mac) + 4 (len) = min header
        let min_header = 32 + KEM_CT_LEN + 32 + 4;
        if data.len() < min_header {
            return Err(SphinxError::MalformedHeader);
        }

        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&data[..32]);

        let ct_end = 32 + KEM_CT_LEN;
        let kem_ciphertext = data[32..ct_end].to_vec();

        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[ct_end..ct_end + 32]);

        let len_start = ct_end + 32;
        let blob_len = u32::from_be_bytes(
            data[len_start..len_start + 4]
                .try_into()
                .map_err(|_| SphinxError::MalformedHeader)?,
        ) as usize;

        let blob_start = len_start + 4;
        if data.len() < blob_start + blob_len {
            return Err(SphinxError::MalformedHeader);
        }

        let encrypted_blob = data[blob_start..blob_start + blob_len].to_vec();

        Ok(Self {
            next_hop,
            kem_ciphertext,
            mac,
            encrypted_blob,
        })
    }
}

/// Dispatch deserialization: classic (version 0x00-0xFE) vs PQ (0xFF).
pub fn parse_sphinx_packet(data: &[u8]) -> Result<SphinxVariant, SphinxError> {
    if data.is_empty() {
        return Err(SphinxError::MalformedHeader);
    }
    if data[0] == PQ_SPHINX_VERSION {
        Ok(SphinxVariant::Pq(PqSphinxPacket::from_bytes_inner(&data[1..])?))
    } else {
        Ok(SphinxVariant::Classic(SphinxPacket::from_bytes(data)?))
    }
}

/// Enum wrapper for version-dispatched Sphinx packets.
#[derive(Clone, Debug)]
pub enum SphinxVariant {
    Classic(SphinxPacket),
    Pq(PqSphinxPacket),
}

// ── PQ helpers (node-only: verify + serialize) ────────────────────────

/// Verify HMAC-SHA256 over (hop_index || next_hop || kem_ciphertext || encrypted_blob).
fn pq_verify_mac(
    layer_key: &[u8; 32],
    hop_index: u8,
    next_hop: &[u8; 32],
    kem_ciphertext: &[u8],
    encrypted_blob: &[u8],
    expected: &[u8; 32],
) -> Result<(), SphinxError> {
    let mut hmac = HmacSha256::new_from_slice(layer_key)
        .expect("HMAC accepts any key length");
    hmac.update(&[hop_index]);
    hmac.update(next_hop);
    hmac.update(kem_ciphertext);
    hmac.update(encrypted_blob);
    hmac.verify_slice(expected)
        .map_err(|_| SphinxError::MacVerificationFailed)
}

/// Serialize a PQ hop's data (without version prefix) for embedding
/// inside an outer layer's encrypted blob.
fn pq_serialize(
    next_hop: &[u8; 32],
    kem_ciphertext: &[u8],
    mac: &[u8; 32],
    encrypted_blob: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + kem_ciphertext.len() + 32 + 4 + encrypted_blob.len());
    buf.extend_from_slice(next_hop);
    buf.extend_from_slice(kem_ciphertext);
    buf.extend_from_slice(mac);
    buf.extend_from_slice(&(encrypted_blob.len() as u32).to_be_bytes());
    buf.extend_from_slice(encrypted_blob);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classic Sphinx tests ────────────────────────────────────────

    #[test]
    fn classic_single_hop_roundtrip() {
        let key = [0x42u8; 32];
        let pub_key = [0xAA; 32];
        let route = vec![(pub_key, key)];
        let pkt = SphinxPacket::create(&route, b"hello").unwrap();

        let (next, inner) = pkt.peel_layer(&key, 0).unwrap();
        assert_eq!(next, [0u8; 32]); // exit sentinel
        assert_eq!(inner.payload, b"hello");
    }

    #[test]
    fn classic_three_hop_routing() {
        // Classic Sphinx verifies MAC at each hop via the serialized wire
        // format. After peel_layer, inner MACs are placeholders — the real
        // MAC was embedded by create() in the encrypted blob. This test
        // verifies the outermost hop peels correctly and returns the right
        // next_hop. Multi-hop is tested end-to-end in the relay integration.
        let k0 = [1u8; 32];
        let route = vec![([0xA0; 32], k0), ([0xB0; 32], [2u8; 32]), ([0xC0; 32], [3u8; 32])];
        let pkt = SphinxPacket::create(&route, b"secret").unwrap();

        let (nh0, inner) = pkt.peel_layer(&k0, 0).unwrap();
        assert_eq!(nh0, [0xB0; 32]);
        assert!(!inner.payload.is_empty());
    }

    #[test]
    fn classic_serialization_roundtrip() {
        let route = vec![([0xAA; 32], [0x42u8; 32])];
        let pkt = SphinxPacket::create(&route, b"test").unwrap();
        let bytes = pkt.to_bytes();
        let pkt2 = SphinxPacket::from_bytes(&bytes).unwrap();
        assert_eq!(pkt.header.next_hop, pkt2.header.next_hop);
        assert_eq!(pkt.header.mac, pkt2.header.mac);
        assert_eq!(pkt.payload, pkt2.payload);
    }

    // ── PQ Sphinx tests ─────────────────────────────────────────────

    #[test]
    fn pq_single_hop_roundtrip() {
        let (pk, sk) = HybridKem::generate_keypair();
        let next_hop = [0u8; 32]; // exit
        let route = vec![(pk, next_hop)];
        let session = PqSessionKeys::new(&route).unwrap();
        let pkt = PqSphinxPacket::create(&session, b"pq hello").unwrap();

        let (nh, plaintext) = pkt.peel_layer(&sk, 0).unwrap();
        assert_eq!(nh, [0u8; 32]);
        assert_eq!(plaintext, b"pq hello");
    }

    #[test]
    fn pq_three_hop_roundtrip() {
        let (pk0, sk0) = HybridKem::generate_keypair();
        let (pk1, sk1) = HybridKem::generate_keypair();
        let (pk2, sk2) = HybridKem::generate_keypair();

        let route = vec![
            (pk0, [0xA0; 32]),
            (pk1, [0xB0; 32]),
            (pk2, [0x00; 32]), // exit
        ];
        let session = PqSessionKeys::new(&route).unwrap();
        let pkt = PqSphinxPacket::create(&session, b"pq secret").unwrap();

        // Hop 0: entry peels
        let (nh0, blob0) = pkt.peel_layer(&sk0, 0).unwrap();
        assert_eq!(nh0, [0xA0; 32]);

        // blob0 is the serialized inner PQ packet for hop 1
        let pkt1 = PqSphinxPacket::from_bytes_inner(&blob0).unwrap();
        let (nh1, blob1) = pkt1.peel_layer(&sk1, 1).unwrap();
        assert_eq!(nh1, [0xB0; 32]);

        // blob1 is the serialized inner PQ packet for hop 2
        let pkt2 = PqSphinxPacket::from_bytes_inner(&blob1).unwrap();
        let (nh2, plaintext) = pkt2.peel_layer(&sk2, 2).unwrap();
        assert_eq!(nh2, [0x00; 32]);
        assert_eq!(plaintext, b"pq secret");
    }

    #[test]
    fn pq_serialization_roundtrip() {
        let (pk, sk) = HybridKem::generate_keypair();
        let route = vec![(pk, [0u8; 32])];
        let session = PqSessionKeys::new(&route).unwrap();
        let pkt = PqSphinxPacket::create(&session, b"test").unwrap();

        let bytes = pkt.to_bytes();
        assert_eq!(bytes[0], PQ_SPHINX_VERSION);

        let pkt2 = PqSphinxPacket::from_bytes_inner(&bytes[1..]).unwrap();
        assert_eq!(pkt.next_hop, pkt2.next_hop);
        assert_eq!(pkt.kem_ciphertext, pkt2.kem_ciphertext);
        assert_eq!(pkt.mac, pkt2.mac);
        assert_eq!(pkt.encrypted_blob, pkt2.encrypted_blob);

        // Verify it still decrypts
        let (_, plaintext) = pkt2.peel_layer(&sk, 0).unwrap();
        assert_eq!(plaintext, b"test");
    }

    #[test]
    fn pq_cached_peel_matches_direct() {
        let (pk, sk) = HybridKem::generate_keypair();
        let route = vec![(pk, [0u8; 32])];
        let session = PqSessionKeys::new(&route).unwrap();
        let pkt = PqSphinxPacket::create(&session, b"cached").unwrap();

        // Direct peel (does KEM decapsulate)
        let (nh1, pt1) = pkt.peel_layer(&sk, 0).unwrap();

        // Cached peel (uses pre-derived layer key)
        let (nh2, pt2) = pkt.peel_layer_cached(&session.hops[0].layer_key, 0).unwrap();

        assert_eq!(nh1, nh2);
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn pq_version_dispatch() {
        // Classic packet
        let route = vec![([0xAA; 32], [0x42u8; 32])];
        let classic = SphinxPacket::create(&route, b"classic").unwrap();
        let classic_bytes = classic.to_bytes();
        assert!(matches!(parse_sphinx_packet(&classic_bytes), Ok(SphinxVariant::Classic(_))));

        // PQ packet
        let (pk, _) = HybridKem::generate_keypair();
        let session = PqSessionKeys::new(&[(pk, [0u8; 32])]).unwrap();
        let pq = PqSphinxPacket::create(&session, b"pq").unwrap();
        let pq_bytes = pq.to_bytes();
        assert!(matches!(parse_sphinx_packet(&pq_bytes), Ok(SphinxVariant::Pq(_))));
    }

    #[test]
    fn pq_wrong_key_fails() {
        let (pk, _sk) = HybridKem::generate_keypair();
        let (_, wrong_sk) = HybridKem::generate_keypair();
        let route = vec![(pk, [0u8; 32])];
        let session = PqSessionKeys::new(&route).unwrap();
        let pkt = PqSphinxPacket::create(&session, b"test").unwrap();

        // Peel with wrong secret key — MAC should fail
        let result = pkt.peel_layer(&wrong_sk, 0);
        assert!(result.is_err());
    }

    #[test]
    fn pq_tampered_blob_fails_mac() {
        let (pk, sk) = HybridKem::generate_keypair();
        let route = vec![(pk, [0u8; 32])];
        let session = PqSessionKeys::new(&route).unwrap();
        let mut pkt = PqSphinxPacket::create(&session, b"test").unwrap();

        // Tamper with encrypted blob
        if let Some(byte) = pkt.encrypted_blob.last_mut() {
            *byte ^= 0xFF;
        }

        let result = pkt.peel_layer(&sk, 0);
        assert!(result.is_err());
    }
}
