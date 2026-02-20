#[cfg(feature = "svm")]
mod tests {
    use std::sync::Arc;
    use tempfile::tempdir;
    use redb::Database;
    use solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        pubkey::Pubkey,
    };
    use layer1::svm::{
        SvmAccountsDB,
        RENT_EPOCH_EXEMPT,
        LAMPORTS_PER_BB,
    };

    fn setup_db() -> Arc<Database> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let db = Database::create(path).unwrap();
        Arc::new(db)
    }

    #[test]
    fn test_store_and_retrieve_account() {
        let db = setup_db();
        let accounts_db = SvmAccountsDB::new(db).unwrap();

        let pubkey = Pubkey::new_unique();
        let account = AccountSharedData::new(
            100 * LAMPORTS_PER_BB,
            0,
            &solana_sdk::system_program::id(),
        );

        // Store in hot state
        accounts_db.store_account(&pubkey, account.clone());

        // Retrieve from hot state
        let retrieved = accounts_db.get_account(&pubkey).unwrap();
        assert_eq!(retrieved.lamports(), 100 * LAMPORTS_PER_BB);
        assert_eq!(retrieved.owner(), &solana_sdk::system_program::id());
        assert_eq!(retrieved.rent_epoch(), RENT_EPOCH_EXEMPT);
    }

    #[test]
    fn test_cache_is_consistent_with_disk() {
        let db = setup_db();
        let pubkey = Pubkey::new_unique();
        let account = AccountSharedData::new(
            50 * LAMPORTS_PER_BB,
            0,
            &solana_sdk::system_program::id(),
        );

        {
            let accounts_db = SvmAccountsDB::new(Arc::clone(&db)).unwrap();
            accounts_db.store_account(&pubkey, account);
            // Flush to disk
            let flushed = accounts_db.flush_block().unwrap();
            assert_eq!(flushed, 1);
        }

        // Re-open DB, should load from disk into cache
        let accounts_db2 = SvmAccountsDB::new(db).unwrap();
        let retrieved = accounts_db2.get_account(&pubkey).unwrap();
        assert_eq!(retrieved.lamports(), 50 * LAMPORTS_PER_BB);
    }

    #[test]
    fn test_batch_store_atomicity() {
        let db = setup_db();
        let accounts_db = SvmAccountsDB::new(db).unwrap();

        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();

        let acc1 = AccountSharedData::new(10, 0, &solana_sdk::system_program::id());
        let acc2 = AccountSharedData::new(20, 0, &solana_sdk::system_program::id());

        accounts_db.store_accounts_batch(&[(pk1, acc1), (pk2, acc2)]);

        assert_eq!(accounts_db.get_lamports(&pk1), 10);
        assert_eq!(accounts_db.get_lamports(&pk2), 20);
        assert_eq!(accounts_db.dirty_count(), 2);

        let flushed = accounts_db.flush_block().unwrap();
        assert_eq!(flushed, 2);
        assert_eq!(accounts_db.dirty_count(), 0);
    }

    #[test]
    fn test_nonexistent_account_returns_none() {
        let db = setup_db();
        let accounts_db = SvmAccountsDB::new(db).unwrap();

        let pubkey = Pubkey::new_unique();
        assert!(accounts_db.get_account(&pubkey).is_none());
        assert_eq!(accounts_db.get_lamports(&pubkey), 0);
        assert!(!accounts_db.account_exists(&pubkey));
    }

    #[test]
    fn test_lamport_overflow_safety() {
        let db = setup_db();
        let accounts_db = SvmAccountsDB::new(db).unwrap();

        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();

        let acc1 = AccountSharedData::new(u64::MAX, 0, &solana_sdk::system_program::id());
        let acc2 = AccountSharedData::new(1, 0, &solana_sdk::system_program::id());

        accounts_db.store_account(&pk1, acc1);
        accounts_db.store_account(&pk2, acc2);

        // Attempt to transfer 1 lamport from pk2 to pk1 (which is at u64::MAX)
        let result = accounts_db.system_transfer(&pk2, &pk1, 1);
        
        assert!(result.is_err());
        if let Err(layer1::svm::SvmError::LamportOverflow) = result {
            // Expected
        } else {
            panic!("Expected LamportOverflow error");
        }
    }
}
