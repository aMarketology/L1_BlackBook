//! P2P Network Layer - Gossipsub over TCP
//! Port 9000 | Peer discovery via mDNS/DHT

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use super::block_proposal::ConsensusMessage;

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
    pub min_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self { listen_port: 9000, bootstrap_peers: vec![], max_peers: 50, min_peers: 3 }
    }
}

// ============================================================================
// PEER INFO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: String,
    pub validator_address: Option<String>,
    pub node_type: PeerNodeType,
    pub connected_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub messages_received: u64,
    pub messages_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum PeerNodeType {
    Validator,
    FullNode,
    #[default]
    Unknown,
}

// ============================================================================
// NETWORK MESSAGES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Consensus(ConsensusMessage),
    Transaction { hash: String, from: String, to: String, amount: u64, sig: String },
    Handshake { peer_id: String, node_type: PeerNodeType, slot: u64 },
    Ping(u64),
    Pong(u64),
    SyncRequest { from_slot: u64, to_slot: u64 },
    SyncResponse { blocks: Vec<Vec<u8>>, has_more: bool },
}

// ============================================================================
// P2P NETWORK
// ============================================================================

pub struct P2PNetwork {
    config: NetworkConfig,
    local_peer_id: Option<String>,
    peers: HashMap<String, PeerInfo>,
    banned: HashSet<String>,
    is_running: bool,
    stats: NetworkStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub peers_connected: u64,
}

impl P2PNetwork {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            local_peer_id: None,
            peers: HashMap::new(),
            banned: HashSet::new(),
            is_running: false,
            stats: NetworkStats::default(),
        }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        self.local_peer_id = Some(generate_peer_id());
        self.is_running = true;
        println!("🌐 P2P on port {}", self.config.listen_port);
        Ok(())
    }

    pub async fn stop(&mut self) {
        self.is_running = false;
        self.peers.clear();
    }

    pub fn broadcast(&mut self, message: NetworkMessage) {
        self.stats.messages_sent += self.peers.len() as u64;
        // In production: gossipsub.publish(topic, message)
    }

    pub fn send_to_peer(&mut self, peer_id: &str, _message: NetworkMessage) -> Result<(), String> {
        if !self.peers.contains_key(peer_id) {
            return Err("peer not connected".into());
        }
        self.stats.messages_sent += 1;
        if let Some(p) = self.peers.get_mut(peer_id) { p.messages_sent += 1; }
        Ok(())
    }

    pub fn handle_message(&mut self, from: &str, msg: NetworkMessage) -> Option<NetworkMessage> {
        self.stats.messages_received += 1;
        if let Some(p) = self.peers.get_mut(from) {
            p.messages_received += 1;
            p.last_seen = Utc::now();
        }

        match msg {
            NetworkMessage::Ping(nonce) => Some(NetworkMessage::Pong(nonce)),
            NetworkMessage::Handshake { node_type, .. } => {
                if let Some(p) = self.peers.get_mut(from) { p.node_type = node_type; }
                None
            }
            _ => None,
        }
    }

    pub fn add_peer(&mut self, peer_id: String, address: String) -> Result<(), String> {
        if self.banned.contains(&peer_id) { return Err("banned".into()); }
        if self.peers.len() >= self.config.max_peers { return Err("max peers".into()); }

        self.peers.insert(peer_id.clone(), PeerInfo {
            peer_id,
            address,
            validator_address: None,
            node_type: PeerNodeType::Unknown,
            connected_at: Utc::now(),
            last_seen: Utc::now(),
            messages_received: 0,
            messages_sent: 0,
        });
        self.stats.peers_connected += 1;
        Ok(())
    }

    pub fn remove_peer(&mut self, peer_id: &str) { self.peers.remove(peer_id); }

    pub fn ban_peer(&mut self, peer_id: &str) {
        self.banned.insert(peer_id.into());
        self.remove_peer(peer_id);
    }

    pub fn get_peers(&self) -> Vec<&PeerInfo> { self.peers.values().collect() }
    pub fn get_peer(&self, id: &str) -> Option<&PeerInfo> { self.peers.get(id) }
    pub fn has_enough_peers(&self) -> bool { self.peers.len() >= self.config.min_peers }
    pub fn get_stats(&self) -> &NetworkStats { &self.stats }
    pub fn local_peer_id(&self) -> Option<&String> { self.local_peer_id.as_ref() }
    pub fn is_running(&self) -> bool { self.is_running }
}

fn generate_peer_id() -> String {
    use sha2::{Sha256, Digest};
    let bytes: [u8; 32] = rand::random();
    format!("12D3KooW{}", hex::encode(&Sha256::digest(&bytes)[..16]))
}
