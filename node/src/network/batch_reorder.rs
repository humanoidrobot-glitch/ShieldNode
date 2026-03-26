//! Packet batching and reordering at each relay hop.
//!
//! Collects incoming packets for a configurable time window, shuffles
//! the order within the batch, and forwards as a group. Breaks timing
//! correlation between input and output packets — an observer cannot
//! match an incoming packet to an outgoing packet based on arrival/
//! departure timing.
//!
//! Adds 25-75ms latency (half the batch window on average). Opt-in
//! because the latency cost is significant for interactive applications.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::net::UdpSocket;
use tracing::{info, warn};

/// Maximum packets per batch (safety cap to bound memory).
const MAX_BATCH_SIZE: usize = 1000;

/// A queued packet waiting to be flushed with its batch.
struct QueuedPacket {
    data: Vec<u8>,
    destination: SocketAddr,
}

/// Per-hop batch buffer that collects, shuffles, and flushes packets.
pub struct BatchBuffer {
    queue: VecDeque<QueuedPacket>,
    window: Duration,
    window_start: Instant,
    total_batches_flushed: u64,
    total_packets_reordered: u64,
}

impl BatchBuffer {
    pub fn new(window_ms: u64) -> Self {
        Self {
            queue: VecDeque::new(),
            window: Duration::from_millis(window_ms),
            window_start: Instant::now(),
            total_batches_flushed: 0,
            total_packets_reordered: 0,
        }
    }

    /// Queue a packet for the current batch.
    pub fn enqueue(&mut self, data: Vec<u8>, destination: SocketAddr) {
        if self.queue.len() >= MAX_BATCH_SIZE {
            self.queue.pop_front();
            warn!("batch queue full, dropping oldest packet");
        }
        self.queue.push_back(QueuedPacket { data, destination });
    }

    /// Check if the current batch window has elapsed and a flush is due.
    pub fn should_flush(&self) -> bool {
        !self.queue.is_empty() && self.window_start.elapsed() >= self.window
    }

    /// Drain the batch, shuffle the packet order, and return the shuffled
    /// packets ready for sending. Resets the window.
    pub fn flush(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
        if self.queue.is_empty() {
            self.window_start = Instant::now();
            return Vec::new();
        }

        let mut packets: Vec<(Vec<u8>, SocketAddr)> = self
            .queue
            .drain(..)
            .map(|p| (p.data, p.destination))
            .collect();

        // Shuffle to break timing correlation.
        let mut rng = rand::thread_rng();
        packets.shuffle(&mut rng);

        self.total_batches_flushed += 1;
        self.total_packets_reordered += packets.len() as u64;
        self.window_start = Instant::now();

        packets
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    pub fn total_batches(&self) -> u64 {
        self.total_batches_flushed
    }

    pub fn total_reordered(&self) -> u64 {
        self.total_packets_reordered
    }

    pub fn window_ms(&self) -> u64 {
        self.window.as_millis() as u64
    }
}

/// Run the batch flush loop. Checks for due batches and sends them.
pub async fn batch_flush_loop(
    stop: Arc<AtomicBool>,
    socket: Arc<UdpSocket>,
    buffer: Arc<tokio::sync::Mutex<BatchBuffer>>,
) {
    // Poll at half the batch window for responsiveness.
    let poll_interval = {
        let buf = buffer.lock().await;
        Duration::from_millis(buf.window_ms().max(10) / 2)
    };

    info!(
        poll_ms = poll_interval.as_millis() as u64,
        "batch reorder loop started"
    );

    loop {
        if stop.load(Ordering::Relaxed) {
            // Flush any remaining packets before stopping.
            let remaining = {
                let mut buf = buffer.lock().await;
                buf.flush()
            };
            for (data, dest) in &remaining {
                let _ = socket.send_to(data, dest).await;
            }
            let buf = buffer.lock().await;
            info!(
                total_batches = buf.total_batches(),
                total_reordered = buf.total_reordered(),
                "batch reorder loop stopped"
            );
            return;
        }

        tokio::time::sleep(poll_interval).await;

        // Single lock: check and flush in one acquisition.
        let packets = {
            let mut buf = buffer.lock().await;
            if buf.should_flush() {
                buf.flush()
            } else {
                continue;
            }
        };

        for (data, dest) in &packets {
            if let Err(e) = socket.send_to(data, dest).await {
                warn!(dest = %dest, error = %e, "batch send failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_and_flush_roundtrip() {
        let mut buf = BatchBuffer::new(50);
        let dest: SocketAddr = "10.0.0.1:51821".parse().unwrap();

        buf.enqueue(vec![1, 2, 3], dest);
        buf.enqueue(vec![4, 5, 6], dest);
        buf.enqueue(vec![7, 8, 9], dest);

        assert_eq!(buf.pending_count(), 3);

        let flushed = buf.flush();
        assert_eq!(flushed.len(), 3);
        assert_eq!(buf.pending_count(), 0);
        assert_eq!(buf.total_batches(), 1);
        assert_eq!(buf.total_reordered(), 3);
    }

    #[test]
    fn flush_empty_is_no_op() {
        let mut buf = BatchBuffer::new(50);
        let flushed = buf.flush();
        assert!(flushed.is_empty());
        assert_eq!(buf.total_batches(), 0);
    }

    #[test]
    fn should_flush_respects_window() {
        let mut buf = BatchBuffer::new(100); // 100ms window
        let dest: SocketAddr = "10.0.0.1:51821".parse().unwrap();

        buf.enqueue(vec![1], dest);
        assert!(!buf.should_flush()); // too soon

        std::thread::sleep(Duration::from_millis(150));
        assert!(buf.should_flush()); // window elapsed
    }

    #[test]
    fn should_flush_false_when_empty() {
        let buf = BatchBuffer::new(0); // zero window
        // Even with zero window, empty queue → no flush.
        assert!(!buf.should_flush());
    }

    #[test]
    fn shuffle_changes_order_statistically() {
        let mut buf = BatchBuffer::new(0);
        let dest: SocketAddr = "10.0.0.1:51821".parse().unwrap();

        // Insert 100 packets with sequential data.
        for i in 0..100u8 {
            buf.enqueue(vec![i], dest);
        }

        let flushed = buf.flush();
        let order: Vec<u8> = flushed.iter().map(|(d, _)| d[0]).collect();

        // Check that the order is NOT sequential (with high probability).
        let sequential: Vec<u8> = (0..100).collect();
        assert_ne!(order, sequential, "100 packets should be shuffled (P(sequential) ≈ 0)");
    }

    #[test]
    fn max_batch_size_enforced() {
        let mut buf = BatchBuffer::new(50);
        let dest: SocketAddr = "10.0.0.1:51821".parse().unwrap();

        // Insert more than MAX_BATCH_SIZE.
        for i in 0..MAX_BATCH_SIZE + 100 {
            buf.enqueue(vec![i as u8], dest);
        }

        assert_eq!(buf.pending_count(), MAX_BATCH_SIZE);
    }

    #[test]
    fn multiple_destinations_preserved() {
        let mut buf = BatchBuffer::new(0);
        let a: SocketAddr = "10.0.0.1:51821".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:51821".parse().unwrap();

        buf.enqueue(vec![1], a);
        buf.enqueue(vec![2], b);
        buf.enqueue(vec![3], a);

        let flushed = buf.flush();
        assert_eq!(flushed.len(), 3);

        // All destinations should be preserved (though order is shuffled).
        let dests: Vec<SocketAddr> = flushed.iter().map(|(_, d)| *d).collect();
        assert!(dests.contains(&a));
        assert!(dests.contains(&b));
    }
}
