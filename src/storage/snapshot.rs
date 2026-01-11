// ============================================================================
// SNAPSHOT SERVICE - State Snapshots for Fast Node Bootstrap
// ============================================================================
//
// Enables new nodes to sync quickly by downloading a recent state snapshot
// instead of replaying the entire blockchain history.
//
// KEY FEATURES:
// 1. FULL SNAPSHOTS: Complete state at epoch boundaries (~12 hours)
// 2. INCREMENTAL SNAPSHOTS: Delta changes every N slots for faster updates
// 3. MANIFEST: Metadata for verification (state_root, slot, accounts_hash)
// 4. STREAMING: Chunked download with parallel verification
//
// Based on Solana's snapshot architecture.
// ============================================================================

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use borsh::{BorshSerialize, BorshDeserialize};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Slots between full snapshots (1 epoch = 432,000 slots ≈ 2 days at 400ms/slot)
pub const FULL_SNAPSHOT_INTERVAL_SLOTS: u64 = 432_000;

/// Slots between incremental snapshots
pub const INCREMENTAL_SNAPSHOT_INTERVAL_SLOTS: u64 = 1_000;

/// Maximum snapshot age before forcing new download
pub const MAX_SNAPSHOT_AGE_SLOTS: u64 = 500_000;

/// Chunk size for streaming downloads (1MB)
pub const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum accounts per chunk for parallel processing
pub const ACCOUNTS_PER_CHUNK: usize = 10_000;

/// Snapshot directory name
pub const SNAPSHOT_DIR: &str = "snapshots";

// ============================================================================
// SNAPSHOT MANIFEST - Metadata for verification
// ============================================================================

/// Manifest describing a snapshot for verification
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Snapshot format version
    pub version: u32,
    
    /// Slot at which snapshot was taken
    pub slot: u64,
    
    /// Block hash at snapshot slot
    pub block_hash: String,
    
    /// Merkle root of all account states
    pub state_root: String,
    
    /// Hash of all account data (for verification)
    pub accounts_hash: String,
    
    /// Total number of accounts
    pub account_count: u64,
    
    /// Total lamports in all accounts
    pub total_lamports: u64,
    
    /// Epoch at snapshot
    pub epoch: u64,
    
    /// Timestamp of snapshot creation
    pub created_at: u64,
    
    /// Size of snapshot in bytes
    pub size_bytes: u64,
    
    /// Number of chunks
    pub chunk_count: u32,
    
    /// Hash of each chunk (for parallel verification)
    pub chunk_hashes: Vec<String>,
    
    /// Whether this is an incremental snapshot
    pub is_incremental: bool,
    
    /// Base slot for incremental (full snapshot this is based on)
    pub base_slot: Option<u64>,
}

impl SnapshotManifest {
    pub fn new(slot: u64, block_hash: String, epoch: u64) -> Self {
        Self {
            version: 1,
            slot,
            block_hash,
            state_root: String::new(),
            accounts_hash: String::new(),
            account_count: 0,
            total_lamports: 0,
            epoch,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            size_bytes: 0,
            chunk_count: 0,
            chunk_hashes: Vec::new(),
            is_incremental: false,
            base_slot: None,
        }
    }
    
    /// Verify manifest integrity
    pub fn verify(&self) -> Result<(), SnapshotError> {
        if self.version != 1 {
            return Err(SnapshotError::UnsupportedVersion(self.version));
        }
        if self.chunk_count as usize != self.chunk_hashes.len() {
            return Err(SnapshotError::ChunkCountMismatch);
        }
        if self.state_root.is_empty() {
            return Err(SnapshotError::MissingStateRoot);
        }
        Ok(())
    }
    
    /// Get snapshot filename
    pub fn filename(&self) -> String {
        if self.is_incremental {
            format!("snapshot-{}-{}.incremental", self.base_slot.unwrap_or(0), self.slot)
        } else {
            format!("snapshot-{}.full", self.slot)
        }
    }
}

// ============================================================================
// ACCOUNT SNAPSHOT - Serialized account state
// ============================================================================

/// Snapshot of a single account
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountSnapshot {
    /// Account address
    pub address: String,
    
    /// Balance in lamports
    pub lamports: u64,
    
    /// Account nonce
    pub nonce: u64,
    
    /// Owner program
    pub owner: String,
    
    /// Is executable (program account)
    pub executable: bool,
    
    /// Rent epoch
    pub rent_epoch: u64,
    
    /// Data hash (actual data stored separately for large accounts)
    pub data_hash: String,
    
    /// Data size
    pub data_size: u32,
    
    /// Last modified slot
    pub last_modified_slot: u64,
}

// ============================================================================
// SNAPSHOT CHUNK - Unit of parallel download/verification
// ============================================================================

/// A chunk of accounts for parallel processing
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SnapshotChunk {
    /// Chunk index
    pub index: u32,
    
    /// Accounts in this chunk
    pub accounts: Vec<AccountSnapshot>,
    
    /// Hash of this chunk
    pub hash: String,
    
    /// Starting account index
    pub start_index: u64,
    
    /// Account data blobs (for accounts with data)
    pub account_data: HashMap<String, Vec<u8>>,
}

impl SnapshotChunk {
    pub fn new(index: u32, start_index: u64) -> Self {
        Self {
            index,
            accounts: Vec::new(),
            hash: String::new(),
            start_index,
            account_data: HashMap::new(),
        }
    }
    
    /// Add account to chunk
    pub fn add_account(&mut self, account: AccountSnapshot, data: Option<Vec<u8>>) {
        if let Some(d) = data {
            self.account_data.insert(account.address.clone(), d);
        }
        self.accounts.push(account);
    }
    
    /// Finalize chunk and compute hash
    pub fn finalize(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        for account in &self.accounts {
            hasher.update(account.address.as_bytes());
            hasher.update(account.lamports.to_le_bytes());
            hasher.update(account.nonce.to_le_bytes());
        }
        self.hash = hex::encode(hasher.finalize());
    }
    
    /// Verify chunk hash
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        for account in &self.accounts {
            hasher.update(account.address.as_bytes());
            hasher.update(account.lamports.to_le_bytes());
            hasher.update(account.nonce.to_le_bytes());
        }
        hex::encode(hasher.finalize()) == self.hash
    }
}

// ============================================================================
// SNAPSHOT WRITER - Creates snapshots
// ============================================================================

/// Writes state snapshots to disk
pub struct SnapshotWriter {
    /// Base directory for snapshots
    snapshot_dir: PathBuf,
    
    /// Current chunk being written
    current_chunk: SnapshotChunk,
    
    /// All chunks
    chunks: Vec<SnapshotChunk>,
    
    /// Manifest being built
    manifest: SnapshotManifest,
}

impl SnapshotWriter {
    pub fn new(base_dir: &Path, slot: u64, block_hash: String, epoch: u64) -> std::io::Result<Self> {
        let snapshot_dir = base_dir.join(SNAPSHOT_DIR);
        fs::create_dir_all(&snapshot_dir)?;
        
        Ok(Self {
            snapshot_dir,
            current_chunk: SnapshotChunk::new(0, 0),
            chunks: Vec::new(),
            manifest: SnapshotManifest::new(slot, block_hash, epoch),
        })
    }
    
    /// Add an account to the snapshot
    pub fn add_account(&mut self, account: AccountSnapshot, data: Option<Vec<u8>>) {
        self.current_chunk.add_account(account.clone(), data);
        self.manifest.account_count += 1;
        self.manifest.total_lamports += account.lamports;
        
        // Start new chunk if current is full
        if self.current_chunk.accounts.len() >= ACCOUNTS_PER_CHUNK {
            self.flush_chunk();
        }
    }
    
    /// Flush current chunk
    fn flush_chunk(&mut self) {
        if self.current_chunk.accounts.is_empty() {
            return;
        }
        
        self.current_chunk.finalize();
        let chunk = std::mem::replace(
            &mut self.current_chunk,
            SnapshotChunk::new(
                self.chunks.len() as u32 + 1,
                self.manifest.account_count,
            ),
        );
        
        self.manifest.chunk_hashes.push(chunk.hash.clone());
        self.chunks.push(chunk);
    }
    
    /// Finalize and write snapshot to disk
    pub fn finalize(mut self, state_root: String) -> std::io::Result<SnapshotManifest> {
        // Flush remaining accounts
        self.flush_chunk();
        
        self.manifest.state_root = state_root;
        self.manifest.chunk_count = self.chunks.len() as u32;
        
        // Compute accounts hash
        let mut hasher = Sha256::new();
        for hash in &self.manifest.chunk_hashes {
            hasher.update(hash.as_bytes());
        }
        self.manifest.accounts_hash = hex::encode(hasher.finalize());
        
        // Write chunks to disk
        let snapshot_path = self.snapshot_dir.join(self.manifest.filename());
        fs::create_dir_all(&snapshot_path)?;
        
        for chunk in &self.chunks {
            let chunk_file = snapshot_path.join(format!("chunk-{:06}.bin", chunk.index));
            let data = borsh::to_vec(chunk).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            })?;
            fs::write(&chunk_file, &data)?;
            self.manifest.size_bytes += data.len() as u64;
        }
        
        // Write manifest
        let manifest_file = snapshot_path.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&self.manifest)?;
        fs::write(manifest_file, manifest_json)?;
        
        println!("📸 Snapshot created: {} accounts, {} chunks, {} bytes",
                 self.manifest.account_count,
                 self.manifest.chunk_count,
                 self.manifest.size_bytes);
        
        Ok(self.manifest)
    }
}

// ============================================================================
// SNAPSHOT READER - Loads snapshots
// ============================================================================

/// Reads state snapshots from disk
pub struct SnapshotReader {
    /// Snapshot directory
    snapshot_path: PathBuf,
    
    /// Loaded manifest
    pub manifest: SnapshotManifest,
}

impl SnapshotReader {
    /// Open a snapshot for reading
    pub fn open(base_dir: &Path, slot: u64) -> Result<Self, SnapshotError> {
        let snapshot_dir = base_dir.join(SNAPSHOT_DIR);
        
        // Find matching snapshot
        let snapshot_name = format!("snapshot-{}.full", slot);
        let snapshot_path = snapshot_dir.join(&snapshot_name);
        
        if !snapshot_path.exists() {
            return Err(SnapshotError::NotFound(slot));
        }
        
        // Load manifest
        let manifest_file = snapshot_path.join("manifest.json");
        let manifest_json = fs::read_to_string(&manifest_file)
            .map_err(|e| SnapshotError::IoError(e.to_string()))?;
        let manifest: SnapshotManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| SnapshotError::ManifestError(e.to_string()))?;
        
        manifest.verify()?;
        
        Ok(Self {
            snapshot_path,
            manifest,
        })
    }
    
    /// Find latest snapshot
    pub fn find_latest(base_dir: &Path) -> Result<Self, SnapshotError> {
        let snapshot_dir = base_dir.join(SNAPSHOT_DIR);
        
        if !snapshot_dir.exists() {
            return Err(SnapshotError::NotFound(0));
        }
        
        let mut latest_slot = 0u64;
        
        for entry in fs::read_dir(&snapshot_dir).map_err(|e| SnapshotError::IoError(e.to_string()))? {
            let entry = entry.map_err(|e| SnapshotError::IoError(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            
            if name.starts_with("snapshot-") && name.ends_with(".full") {
                if let Some(slot_str) = name.strip_prefix("snapshot-").and_then(|s| s.strip_suffix(".full")) {
                    if let Ok(slot) = slot_str.parse::<u64>() {
                        latest_slot = latest_slot.max(slot);
                    }
                }
            }
        }
        
        if latest_slot == 0 {
            return Err(SnapshotError::NotFound(0));
        }
        
        Self::open(base_dir, latest_slot)
    }
    
    /// Read a specific chunk
    pub fn read_chunk(&self, index: u32) -> Result<SnapshotChunk, SnapshotError> {
        if index >= self.manifest.chunk_count {
            return Err(SnapshotError::ChunkNotFound(index));
        }
        
        let chunk_file = self.snapshot_path.join(format!("chunk-{:06}.bin", index));
        let data = fs::read(&chunk_file)
            .map_err(|e| SnapshotError::IoError(e.to_string()))?;
        
        let chunk: SnapshotChunk = borsh::from_slice(&data)
            .map_err(|e| SnapshotError::DeserializationError(e.to_string()))?;
        
        // Verify chunk hash
        if !chunk.verify() {
            return Err(SnapshotError::ChunkVerificationFailed(index));
        }
        
        // Verify against manifest
        if self.manifest.chunk_hashes.get(index as usize) != Some(&chunk.hash) {
            return Err(SnapshotError::ChunkHashMismatch(index));
        }
        
        Ok(chunk)
    }
    
    /// Iterate over all accounts in snapshot
    pub fn iter_accounts(&self) -> SnapshotAccountIterator {
        SnapshotAccountIterator {
            reader: self,
            current_chunk: 0,
            current_index: 0,
            loaded_chunk: None,
        }
    }
}

/// Iterator over accounts in a snapshot
pub struct SnapshotAccountIterator<'a> {
    reader: &'a SnapshotReader,
    current_chunk: u32,
    current_index: usize,
    loaded_chunk: Option<SnapshotChunk>,
}

impl<'a> Iterator for SnapshotAccountIterator<'a> {
    type Item = Result<AccountSnapshot, SnapshotError>;
    
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Load chunk if needed
            if self.loaded_chunk.is_none() {
                if self.current_chunk >= self.reader.manifest.chunk_count {
                    return None;
                }
                match self.reader.read_chunk(self.current_chunk) {
                    Ok(chunk) => {
                        self.loaded_chunk = Some(chunk);
                        self.current_index = 0;
                    }
                    Err(e) => return Some(Err(e)),
                }
            }
            
            // Get account from current chunk
            if let Some(ref chunk) = self.loaded_chunk {
                if self.current_index < chunk.accounts.len() {
                    let account = chunk.accounts[self.current_index].clone();
                    self.current_index += 1;
                    return Some(Ok(account));
                } else {
                    // Move to next chunk
                    self.loaded_chunk = None;
                    self.current_chunk += 1;
                }
            }
        }
    }
}

// ============================================================================
// SNAPSHOT SERVICE - Background snapshot management
// ============================================================================

/// Background service for creating and managing snapshots
pub struct SnapshotService {
    /// Base directory
    base_dir: PathBuf,
    
    /// Latest full snapshot slot
    pub latest_full_snapshot: Arc<RwLock<u64>>,
    
    /// Latest incremental snapshot slot
    pub latest_incremental_snapshot: Arc<RwLock<u64>>,
    
    /// Available snapshots
    pub available_snapshots: Arc<RwLock<Vec<SnapshotManifest>>>,
    
    /// Is snapshot in progress
    snapshot_in_progress: Arc<RwLock<bool>>,
}

impl SnapshotService {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            latest_full_snapshot: Arc::new(RwLock::new(0)),
            latest_incremental_snapshot: Arc::new(RwLock::new(0)),
            available_snapshots: Arc::new(RwLock::new(Vec::new())),
            snapshot_in_progress: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Check if a snapshot should be taken at this slot
    pub fn should_take_snapshot(&self, slot: u64, epoch: u64) -> SnapshotType {
        let last_full = *self.latest_full_snapshot.read();
        let last_incremental = *self.latest_incremental_snapshot.read();
        
        // Full snapshot at epoch boundaries
        if slot > 0 && slot % FULL_SNAPSHOT_INTERVAL_SLOTS == 0 && slot > last_full {
            return SnapshotType::Full;
        }
        
        // Incremental snapshot every N slots (if we have a base)
        if last_full > 0 
            && slot > 0 
            && slot % INCREMENTAL_SNAPSHOT_INTERVAL_SLOTS == 0 
            && slot > last_incremental {
            return SnapshotType::Incremental;
        }
        
        SnapshotType::None
    }
    
    /// Start creating a snapshot (returns immediately, snapshot created in background)
    pub fn start_snapshot<F>(
        &self,
        slot: u64,
        block_hash: String,
        epoch: u64,
        snapshot_type: SnapshotType,
        account_iterator: F,
    ) -> Result<(), SnapshotError>
    where
        F: FnOnce(&mut SnapshotWriter) -> Result<String, SnapshotError> + Send + 'static,
    {
        // Check if already in progress
        {
            let mut in_progress = self.snapshot_in_progress.write();
            if *in_progress {
                return Err(SnapshotError::AlreadyInProgress);
            }
            *in_progress = true;
        }
        
        let base_dir = self.base_dir.clone();
        let latest_full = self.latest_full_snapshot.clone();
        let latest_incremental = self.latest_incremental_snapshot.clone();
        let available = self.available_snapshots.clone();
        let in_progress = self.snapshot_in_progress.clone();
        
        // Create snapshot (in this simple version, synchronously)
        // In production, spawn this as a background task
        let result = (|| {
            let mut writer = SnapshotWriter::new(&base_dir, slot, block_hash, epoch)
                .map_err(|e| SnapshotError::IoError(e.to_string()))?;
            
            if snapshot_type == SnapshotType::Incremental {
                writer.manifest.is_incremental = true;
                writer.manifest.base_slot = Some(*latest_full.read());
            }
            
            let state_root = account_iterator(&mut writer)?;
            let manifest = writer.finalize(state_root)
                .map_err(|e| SnapshotError::IoError(e.to_string()))?;
            
            // Update tracking
            match snapshot_type {
                SnapshotType::Full => {
                    *latest_full.write() = slot;
                }
                SnapshotType::Incremental => {
                    *latest_incremental.write() = slot;
                }
                SnapshotType::None => {}
            }
            
            available.write().push(manifest);
            
            Ok(())
        })();
        
        *in_progress.write() = false;
        result
    }
    
    /// Get latest available snapshot manifest
    pub fn get_latest_manifest(&self) -> Option<SnapshotManifest> {
        self.available_snapshots.read().last().cloned()
    }
    
    /// Clean up old snapshots (keep last N)
    pub fn cleanup_old_snapshots(&self, keep_count: usize) -> std::io::Result<()> {
        let snapshot_dir = self.base_dir.join(SNAPSHOT_DIR);
        
        let mut snapshots: Vec<_> = fs::read_dir(&snapshot_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        
        // Sort by name (which includes slot number)
        snapshots.sort_by_key(|e| e.file_name());
        
        // Remove old ones
        while snapshots.len() > keep_count {
            if let Some(old) = snapshots.first() {
                println!("🗑️ Removing old snapshot: {:?}", old.file_name());
                fs::remove_dir_all(old.path())?;
            }
            snapshots.remove(0);
        }
        
        Ok(())
    }
}

// ============================================================================
// TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotType {
    None,
    Full,
    Incremental,
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum SnapshotError {
    NotFound(u64),
    UnsupportedVersion(u32),
    ChunkCountMismatch,
    MissingStateRoot,
    ChunkNotFound(u32),
    ChunkVerificationFailed(u32),
    ChunkHashMismatch(u32),
    IoError(String),
    ManifestError(String),
    DeserializationError(String),
    AlreadyInProgress,
    InvalidState(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::NotFound(slot) => write!(f, "Snapshot not found for slot {}", slot),
            SnapshotError::UnsupportedVersion(v) => write!(f, "Unsupported snapshot version: {}", v),
            SnapshotError::ChunkCountMismatch => write!(f, "Chunk count mismatch in manifest"),
            SnapshotError::MissingStateRoot => write!(f, "Missing state root in manifest"),
            SnapshotError::ChunkNotFound(i) => write!(f, "Chunk {} not found", i),
            SnapshotError::ChunkVerificationFailed(i) => write!(f, "Chunk {} verification failed", i),
            SnapshotError::ChunkHashMismatch(i) => write!(f, "Chunk {} hash mismatch", i),
            SnapshotError::IoError(e) => write!(f, "IO error: {}", e),
            SnapshotError::ManifestError(e) => write!(f, "Manifest error: {}", e),
            SnapshotError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            SnapshotError::AlreadyInProgress => write!(f, "Snapshot already in progress"),
            SnapshotError::InvalidState(e) => write!(f, "Invalid state: {}", e),
        }
    }
}

impl std::error::Error for SnapshotError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_snapshot_manifest() {
        let mut manifest = SnapshotManifest::new(100, "blockhash".to_string(), 1);
        manifest.state_root = "stateroot".to_string();
        manifest.chunk_count = 2;
        manifest.chunk_hashes = vec!["hash1".to_string(), "hash2".to_string()];
        
        assert!(manifest.verify().is_ok());
        assert_eq!(manifest.filename(), "snapshot-100.full");
    }
    
    #[test]
    fn test_snapshot_chunk() {
        let mut chunk = SnapshotChunk::new(0, 0);
        
        let account = AccountSnapshot {
            address: "L1_TEST".to_string(),
            lamports: 1000,
            nonce: 1,
            owner: "system".to_string(),
            executable: false,
            rent_epoch: 0,
            data_hash: "".to_string(),
            data_size: 0,
            last_modified_slot: 0,
        };
        
        chunk.add_account(account, None);
        chunk.finalize();
        
        assert!(!chunk.hash.is_empty());
        assert!(chunk.verify());
    }
    
    #[test]
    fn test_snapshot_service_timing() {
        let service = SnapshotService::new(PathBuf::from("/tmp"));
        
        // No snapshot at slot 0
        assert_eq!(service.should_take_snapshot(0, 0), SnapshotType::None);
        
        // Full snapshot at epoch boundary
        assert_eq!(
            service.should_take_snapshot(FULL_SNAPSHOT_INTERVAL_SLOTS, 1), 
            SnapshotType::Full
        );
    }
}
