//! Fixed-size packet normalization.
//!
//! Enforces a uniform outer packet size (NORMALIZED_SIZE bytes) for all tunnel
//! traffic, eliminating packet-size fingerprinting. An observer capturing
//! traffic sees a stream of identically-sized ciphertext blobs.
//!
//! Wire format per normalized frame:
//! ```text
//! [2-byte sequence_number BE][1-byte fragment_index][1-byte fragment_count][payload...][random padding]
//! ```
//!
//! Total frame: NORMALIZED_SIZE bytes (header + payload + padding).

use rand::Rng;

/// The fixed outer packet size in bytes.
pub const NORMALIZED_SIZE: usize = 1280;

/// Header: sequence (2) + fragment_index (1) + fragment_count (1).
const HEADER_LEN: usize = 4;

/// Maximum payload per normalized frame (minus 2-byte length footer).
const MAX_PAYLOAD: usize = NORMALIZED_SIZE - HEADER_LEN - 2;

/// A single normalized frame ready for transmission.
pub struct NormalizedFrame {
    pub data: [u8; NORMALIZED_SIZE],
}

/// Sequence number counter (wraps at u16::MAX).
pub struct SequenceCounter {
    next: u16,
}

impl SequenceCounter {
    pub fn new() -> Self {
        Self { next: 0 }
    }

    fn next_seq(&mut self) -> u16 {
        let seq = self.next;
        self.next = self.next.wrapping_add(1);
        seq
    }
}

impl Default for SequenceCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a variable-length packet into one or more fixed-size frames.
///
/// - Packets ≤ MAX_PAYLOAD bytes: padded with random bytes → 1 frame.
/// - Packets > MAX_PAYLOAD bytes: split into ceil(len / MAX_PAYLOAD) frames.
pub fn normalize(packet: &[u8], seq: &mut SequenceCounter) -> Vec<NormalizedFrame> {
    if packet.is_empty() {
        return Vec::new();
    }

    let fragment_count = (packet.len() + MAX_PAYLOAD - 1) / MAX_PAYLOAD;
    let fragment_count_u8 = (fragment_count as u8).min(255);
    let sequence = seq.next_seq();
    let mut rng = rand::thread_rng();

    let mut frames = Vec::with_capacity(fragment_count);

    for frag_idx in 0..fragment_count {
        let offset = frag_idx * MAX_PAYLOAD;
        let end = (offset + MAX_PAYLOAD).min(packet.len());
        let payload_slice = &packet[offset..end];
        let payload_len = payload_slice.len();

        let mut data = [0u8; NORMALIZED_SIZE];

        // Header
        data[0..2].copy_from_slice(&sequence.to_be_bytes());
        data[2] = frag_idx as u8;
        data[3] = fragment_count_u8;

        // Payload
        data[HEADER_LEN..HEADER_LEN + payload_len].copy_from_slice(payload_slice);

        // Random padding for remaining bytes (indistinguishable from ciphertext).
        for byte in &mut data[HEADER_LEN + payload_len..] {
            *byte = rng.gen();
        }

        // Embed actual payload length in the last 2 bytes of the frame so the
        // receiver knows where payload ends and padding begins.
        let len_bytes = (payload_len as u16).to_be_bytes();
        data[NORMALIZED_SIZE - 2] = len_bytes[0];
        data[NORMALIZED_SIZE - 1] = len_bytes[1];

        frames.push(NormalizedFrame { data });
    }

    frames
}

/// Reassembly buffer for collecting fragments of a single packet.
pub struct ReassemblyBuffer {
    fragments: Vec<Option<Vec<u8>>>,
    expected_count: u8,
    received: u8,
}

impl ReassemblyBuffer {
    fn new(fragment_count: u8) -> Self {
        Self {
            fragments: vec![None; fragment_count as usize],
            expected_count: fragment_count,
            received: 0,
        }
    }

    /// Insert a fragment. Returns the reassembled packet if all fragments arrived.
    fn insert(&mut self, index: u8, payload: Vec<u8>) -> Option<Vec<u8>> {
        let idx = index as usize;
        if idx >= self.fragments.len() {
            return None;
        }
        if self.fragments[idx].is_none() {
            self.received += 1;
        }
        self.fragments[idx] = Some(payload);

        if self.received == self.expected_count {
            let mut result = Vec::new();
            for frag in &self.fragments {
                if let Some(data) = frag {
                    result.extend_from_slice(data);
                }
            }
            Some(result)
        } else {
            None
        }
    }
}

/// Manages reassembly of fragmented normalized packets.
pub struct Denormalizer {
    /// sequence_number → ReassemblyBuffer
    pending: std::collections::HashMap<u16, ReassemblyBuffer>,
}

impl Denormalizer {
    pub fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
        }
    }

    /// Process a received normalized frame. Returns the original packet
    /// if this frame completes reassembly, or None if more fragments are needed.
    pub fn denormalize(&mut self, frame: &[u8; NORMALIZED_SIZE]) -> Option<Vec<u8>> {
        let sequence = u16::from_be_bytes([frame[0], frame[1]]);
        let frag_index = frame[2];
        let frag_count = frame[3];

        if frag_count == 0 {
            return None;
        }

        // Extract payload length from the last 2 bytes.
        let payload_len =
            u16::from_be_bytes([frame[NORMALIZED_SIZE - 2], frame[NORMALIZED_SIZE - 1]]) as usize;

        if payload_len > MAX_PAYLOAD {
            return None;
        }

        let payload = frame[HEADER_LEN..HEADER_LEN + payload_len].to_vec();

        if frag_count == 1 {
            // Single-frame packet — no reassembly needed.
            return Some(payload);
        }

        let buffer = self
            .pending
            .entry(sequence)
            .or_insert_with(|| ReassemblyBuffer::new(frag_count));

        let result = buffer.insert(frag_index, payload);

        if result.is_some() {
            self.pending.remove(&sequence);
        }

        result
    }

    /// Evict stale reassembly buffers (incomplete fragments).
    /// Call periodically to prevent memory leaks from dropped fragments.
    pub fn evict_stale(&mut self) {
        // Simple strategy: if we have more than 256 pending, drop the oldest.
        // A proper implementation would use timestamps.
        if self.pending.len() > 256 {
            let oldest = *self.pending.keys().next()
                .expect("pending must be non-empty when len > 256");
            self.pending.remove(&oldest);
        }
    }
}

impl Default for Denormalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_packet_normalizes_to_one_frame() {
        let mut seq = SequenceCounter::new();
        let data = vec![42u8; 100];
        let frames = normalize(&data, &mut seq);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data.len(), NORMALIZED_SIZE);
    }

    #[test]
    fn all_frames_are_fixed_size() {
        let mut seq = SequenceCounter::new();
        let data = vec![0xAB; 3000]; // requires multiple fragments
        let frames = normalize(&data, &mut seq);
        assert!(frames.len() > 1);
        for frame in &frames {
            assert_eq!(frame.data.len(), NORMALIZED_SIZE);
        }
    }

    #[test]
    fn normalize_denormalize_roundtrip_small() {
        let mut seq = SequenceCounter::new();
        let mut denorm = Denormalizer::new();
        let original = b"hello shieldnode".to_vec();
        let frames = normalize(&original, &mut seq);
        assert_eq!(frames.len(), 1);
        let result = denorm.denormalize(&frames[0].data).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn normalize_denormalize_roundtrip_large() {
        let mut seq = SequenceCounter::new();
        let mut denorm = Denormalizer::new();
        let original: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frames = normalize(&original, &mut seq);
        assert!(frames.len() >= 3); // 3000 / 1276 ≈ 2.35 → 3 frames

        let mut result = None;
        for frame in &frames {
            result = denorm.denormalize(&frame.data);
        }
        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn empty_packet_produces_no_frames() {
        let mut seq = SequenceCounter::new();
        let frames = normalize(&[], &mut seq);
        assert!(frames.is_empty());
    }

    #[test]
    fn max_payload_fits_in_one_frame() {
        let mut seq = SequenceCounter::new();
        let mut denorm = Denormalizer::new();
        let original = vec![0xFF; MAX_PAYLOAD];
        let frames = normalize(&original, &mut seq);
        assert_eq!(frames.len(), 1);
        let result = denorm.denormalize(&frames[0].data).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn sequence_numbers_increment() {
        let mut seq = SequenceCounter::new();
        let data = vec![1u8; 10];
        let f1 = normalize(&data, &mut seq);
        let f2 = normalize(&data, &mut seq);
        let s1 = u16::from_be_bytes([f1[0].data[0], f1[0].data[1]]);
        let s2 = u16::from_be_bytes([f2[0].data[0], f2[0].data[1]]);
        assert_eq!(s2, s1 + 1);
    }
}
