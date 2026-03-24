use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::{
    gossipsub, identify, kad, mdns, swarm::NetworkBehaviour, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use thiserror::Error;
use tracing::info;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("swarm build error: {0}")]
    SwarmBuild(String),
    #[error("listen error: {0}")]
    Listen(String),
    #[error("DHT put error: {0}")]
    DhtPut(String),
    #[error("transport error: {0}")]
    Transport(String),
}

// ── composite behaviour ────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct ShieldNodeBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
}

// ── discovery service ──────────────────────────────────────────────────

/// Manages the libp2p swarm for peer discovery and gossip.
pub struct DiscoveryService {
    pub swarm: Swarm<ShieldNodeBehaviour>,
    pub local_peer_id: PeerId,
}

impl DiscoveryService {
    /// Build a new discovery service that listens on `port`.
    pub async fn new(port: u16) -> Result<Self, DiscoveryError> {
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| DiscoveryError::Transport(e.to_string()))?
            .with_behaviour(|key| {
                // Kademlia
                let peer_id = key.public().to_peer_id();
                let store = kad::store::MemoryStore::new(peer_id);
                let kademlia = kad::Behaviour::new(peer_id, store);

                // Gossipsub
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut hasher = DefaultHasher::new();
                    message.data.hash(&mut hasher);
                    gossipsub::MessageId::from(hasher.finish().to_string())
                };
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(|e| format!("gossipsub config: {e}"))?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(|e| format!("gossipsub behaviour: {e}"))?;

                // mDNS
                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .map_err(|e| format!("mdns behaviour: {e}"))?;

                // Identify
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/shieldnode/id/1.0.0".to_string(),
                    key.public(),
                ));

                Ok(ShieldNodeBehaviour {
                    kademlia,
                    gossipsub,
                    mdns,
                    identify,
                })
            })
            .map_err(|e| DiscoveryError::SwarmBuild(e.to_string()))?
            .build();

        let local_peer_id = *swarm.local_peer_id();

        let mut svc = Self {
            swarm,
            local_peer_id,
        };

        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}")
            .parse()
            .map_err(|e| DiscoveryError::Listen(format!("invalid multiaddr: {e}")))?;
        svc.swarm
            .listen_on(listen_addr)
            .map_err(|e| DiscoveryError::Listen(e.to_string()))?;

        info!(%local_peer_id, port, "libp2p swarm started");

        Ok(svc)
    }

    /// Publish this node's information to the Kademlia DHT.
    pub fn announce_node(&mut self, info_bytes: Vec<u8>) -> Result<(), DiscoveryError> {
        let key = kad::RecordKey::new(&format!("/shieldnode/node/{}", self.local_peer_id));
        let record = kad::Record {
            key,
            value: info_bytes,
            publisher: Some(self.local_peer_id),
            expires: None,
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
            .map_err(|e| DiscoveryError::DhtPut(format!("{e:?}")))?;
        info!("announced node to DHT");
        Ok(())
    }

    /// Query the DHT for available ShieldNode peers.
    pub fn discover_nodes(&mut self) {
        let key = kad::RecordKey::new(&"/shieldnode/nodes");
        self.swarm.behaviour_mut().kademlia.get_record(key);
        info!("initiated DHT discovery query");
    }
}
