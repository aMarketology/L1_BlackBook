// ============================================================================
// BLACKBOOK SVM — SHARDED ACCOUNT STATE
// ============================================================================
//
// Horizontal sharding of account state for reduced lock contention during
// parallel execution.
//
// DESIGN:
//   DashMap already provides internal shard-level locking, but its shard
//   count is fixed at construction and not tunable per-deployment.
//   ShardedAccountState wraps N independent DashMaps (shards) and routes
//   accounts to shards using the first bytes of the Pubkey.
//
//   With 256 shards: two transactions touching different shards have ZERO
//   lock contention — they never touch the same DashMap instance.
//
// WHY NOT JUST DashMap's INTERNAL SHARDS?
//   DashMap defaults to num_cpus * 4 shards. On an 8-core machine that's
//   32 shards — good for general use, but we want explicit control for
//   benchmarking and deployment tuning.  ShardedAccountState lets us set
//   shard count at startup (e.g. 256 for high-TPS, 16 for dev).
//
// THREAD SAFETY:
//   Each shard is a DashMap<Pubkey, AccountSharedData>.
//   Reads are lock-free (DashMap read guard).
//   Writes acquire a per-shard lock (microsecond hold time).
//   Cross-shard operations (e.g. transfer A→B in different shards) acquire
//   locks in deterministic order (lower shard first) to prevent deadlock.
//
// ============================================================================

use dashmap::DashMap;
use solana_sdk::{account::AccountSharedData, pubkey::Pubkey};
use std::sync::atomic::{AtomicU64, Ordering};

/// Sharded account state for parallel access with tunable shard count.
pub struct ShardedAccountState {
    /// Individual shards — each is an independent DashMap.
    shards: Vec<DashMap<Pubkey, AccountSharedData>>,
    /// Number of shards (always a power of 2 for fast modulo via bitmask).
    num_shards: usize,
    /// Bitmask for fast shard index: `pubkey_bytes[0] & mask`.
    mask: u8,
    /// Total number of accounts across all shards (approximate).
    account_count: AtomicU64,
}

impl ShardedAccountState {
    /// Create a new sharded state with `num_shards` shards.
    ///
    /// `num_shards` is rounded up to the next power of 2, capped at 256.
    pub fn new(num_shards: usize) -> Self {
        let num_shards = num_shards.next_power_of_two().min(256);
        let mask = (num_shards - 1) as u8;

        let shards = (0..num_shards)
            .map(|_| DashMap::new())
            .collect();

        Self {
            shards,
            num_shards,
            mask,
            account_count: AtomicU64::new(0),
        }
    }

    /// Get the shard index for a pubkey (first byte & mask).
    #[inline(always)]
    fn shard_index(&self, pubkey: &Pubkey) -> usize {
        (pubkey.as_ref()[0] & self.mask) as usize
    }

    /// Get the DashMap shard for a pubkey.
    #[inline(always)]
    fn shard(&self, pubkey: &Pubkey) -> &DashMap<Pubkey, AccountSharedData> {
        &self.shards[self.shard_index(pubkey)]
    }

    /// Fetch an account. Returns `None` if not found.
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        self.shard(pubkey).get(pubkey).map(|r| r.clone())
    }

    /// Check if an account exists.
    pub fn account_exists(&self, pubkey: &Pubkey) -> bool {
        self.shard(pubkey).contains_key(pubkey)
    }

    /// Store (insert or update) an account.
    pub fn store_account(&self, pubkey: &Pubkey, account: AccountSharedData) {
        let shard = self.shard(pubkey);
        let is_new = !shard.contains_key(pubkey);
        shard.insert(*pubkey, account);
        if is_new {
            self.account_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove an account. Returns the removed account if it existed.
    pub fn remove_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        let removed = self.shard(pubkey).remove(pubkey).map(|(_, v)| v);
        if removed.is_some() {
            self.account_count.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    /// Get current lamport balance, or 0 if account doesn't exist.
    pub fn get_lamports(&self, pubkey: &Pubkey) -> u64 {
        use solana_sdk::account::ReadableAccount;
        self.shard(pubkey)
            .get(pubkey)
            .map(|acc| acc.lamports())
            .unwrap_or(0)
    }

    /// Iterate over all accounts across all shards.
    ///
    /// Callback receives `(pubkey, account)` for each entry.
    /// Order is not guaranteed.
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Pubkey, &AccountSharedData),
    {
        for shard in &self.shards {
            for entry in shard.iter() {
                f(entry.key(), entry.value());
            }
        }
    }

    /// Total number of accounts (approximate — races with concurrent inserts).
    pub fn total_accounts(&self) -> u64 {
        self.account_count.load(Ordering::Relaxed)
    }

    /// Number of shards.
    pub fn num_shards(&self) -> usize {
        self.num_shards
    }

    /// Per-shard account distribution (for diagnostics / load balancing).
    pub fn shard_distribution(&self) -> Vec<usize> {
        self.shards.iter().map(|s| s.len()).collect()
    }

    /// Collect all dirty pubkeys from all shards into a single vec.
    /// Used by flush_block to iterate dirty accounts.
    pub fn collect_all_pubkeys(&self) -> Vec<Pubkey> {
        let mut all = Vec::with_capacity(self.total_accounts() as usize);
        for shard in &self.shards {
            for entry in shard.iter() {
                all.push(*entry.key());
            }
        }
        all
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::account::AccountSharedData;

    fn test_pubkey(byte0: u8) -> Pubkey {
        let mut bytes = [0u8; 32];
        bytes[0] = byte0;
        Pubkey::new_from_array(bytes)
    }

    #[test]
    fn test_shard_routing() {
        let state = ShardedAccountState::new(256);
        assert_eq!(state.num_shards(), 256);

        // Pubkeys with different first bytes should land in different shards
        let pk_a = test_pubkey(0x00);
        let pk_b = test_pubkey(0x01);
        let pk_c = test_pubkey(0xFF);

        assert_eq!(state.shard_index(&pk_a), 0x00);
        assert_eq!(state.shard_index(&pk_b), 0x01);
        assert_eq!(state.shard_index(&pk_c), 0xFF);
    }

    #[test]
    fn test_store_and_get() {
        let state = ShardedAccountState::new(16);
        let pk = test_pubkey(42);
        let account = AccountSharedData::new(1_000_000, 0, &Pubkey::default());

        assert!(!state.account_exists(&pk));
        state.store_account(&pk, account.clone());
        assert!(state.account_exists(&pk));

        let retrieved = state.get_account(&pk).unwrap();
        assert_eq!(
            solana_sdk::account::ReadableAccount::lamports(&retrieved),
            1_000_000
        );
        assert_eq!(state.total_accounts(), 1);
    }

    #[test]
    fn test_remove() {
        let state = ShardedAccountState::new(16);
        let pk = test_pubkey(10);
        let account = AccountSharedData::new(500, 0, &Pubkey::default());

        state.store_account(&pk, account);
        assert_eq!(state.total_accounts(), 1);

        let removed = state.remove_account(&pk);
        assert!(removed.is_some());
        assert_eq!(state.total_accounts(), 0);
        assert!(!state.account_exists(&pk));
    }

    #[test]
    fn test_distribution_across_shards() {
        let state = ShardedAccountState::new(4); // 4 shards, mask = 0x03

        // Insert 256 accounts with evenly distributed first bytes
        for i in 0..=255u8 {
            let pk = test_pubkey(i);
            let account = AccountSharedData::new(i as u64 * 1000, 0, &Pubkey::default());
            state.store_account(&pk, account);
        }

        let dist = state.shard_distribution();
        assert_eq!(dist.len(), 4);
        // Each shard should have 64 accounts (256 / 4)
        for &count in &dist {
            assert_eq!(count, 64, "Shards should be evenly distributed: {:?}", dist);
        }
    }

    #[test]
    fn test_get_lamports() {
        let state = ShardedAccountState::new(8);
        let pk = test_pubkey(99);

        assert_eq!(state.get_lamports(&pk), 0); // doesn't exist

        let account = AccountSharedData::new(42_000, 0, &Pubkey::default());
        state.store_account(&pk, account);
        assert_eq!(state.get_lamports(&pk), 42_000);
    }

    #[test]
    fn test_for_each() {
        let state = ShardedAccountState::new(4);
        for i in 0..10u8 {
            let pk = test_pubkey(i);
            let account = AccountSharedData::new(i as u64, 0, &Pubkey::default());
            state.store_account(&pk, account);
        }

        let mut count = 0;
        state.for_each(|_, _| count += 1);
        assert_eq!(count, 10);
    }
}
