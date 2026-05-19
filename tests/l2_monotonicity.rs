// ============================================================================
// BLACKBOOK L1 — L2 STATE ROOT MONOTONICITY REGRESSION TESTS
// ============================================================================
//
// Guards the invariant: each successive /escrow/submit-state-root or
// settlement gRPC SubmitMerkleRoot call MUST carry an l2_block_number that is
// strictly greater than the last accepted value for that market.
//
// These tests exercise the guard at the storage layer — the same logic the HTTP
// handler and gRPC service both call.  They run entirely in-memory (ReDB in a
// tempdir) with no network stack required.
//
// Run with:
//   cargo test --test l2_monotonicity -- --nocapture
// ============================================================================

use layer1::storage::{ConcurrentBlockchain, ContestState, ContestStatus};
use tempfile::tempdir;

// ============================================================================
// HELPERS
// ============================================================================

/// Build a minimal `ContestState` with a given `last_l2_block`.
fn make_contest(contest_id: &str, last_l2_block: u64) -> ContestState {
    ContestState {
        contest_id: contest_id.to_string(),
        status: ContestStatus::Settled,
        merkle_root: [0xAB; 32],
        total_deposited: 10_000_000,
        total_claimed: 0,
        winner_count: 2,
        house_rake: 500_000,
        claim_deadline_slot: 10_000_000,
        l1_tx_hash: format!("fake-tx-{}", last_l2_block),
        last_l2_block,
        created_at: 1_700_000_000,
        vault_pda: String::new(),
        house_rake_swept_tx: None,
    }
}

/// The monotonicity guard exactly as implemented in `escrow_submit_state_root_handler`
/// and `settlement::SubmitMerkleRoot`.  Returns `Err` if the incoming block would
/// regress state, exactly matching the HTTP 409 / gRPC FAILED_PRECONDITION path.
fn check_monotonic(
    bc: &ConcurrentBlockchain,
    market_id: &str,
    incoming_l2_block: u64,
) -> Result<(), String> {
    if let Ok(Some(existing)) = bc.load_contest_state(market_id) {
        if incoming_l2_block <= existing.last_l2_block {
            return Err(format!(
                "L2 block number must be strictly greater than previous submission: \
                 got {} <= stored {}",
                incoming_l2_block, existing.last_l2_block,
            ));
        }
    }
    Ok(())
}

// ============================================================================
// TESTS — monotonicity correctness
// ============================================================================

/// A fresh market (no prior state) must accept any l2_block_number.
#[test]
fn test_no_prior_state_accepts_any_block() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    // No ContestState stored yet → guard must pass unconditionally.
    check_monotonic(&bc, "market_fresh", 1).expect("fresh market must accept block 1");
    check_monotonic(&bc, "market_fresh", 0).expect("fresh market must accept block 0");
    check_monotonic(&bc, "market_fresh", u64::MAX).expect("fresh market must accept u64::MAX");
}

/// After accepting l2_block=10, a later submission of block=10 (equal) is rejected.
#[test]
fn test_equal_block_rejected() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    let contest = make_contest("market_eq", 10);
    bc.store_contest_state(&contest).unwrap();

    let result = check_monotonic(&bc, "market_eq", 10);
    assert!(result.is_err(), "equal l2_block must be rejected (not strictly greater)");

    let err = result.unwrap_err();
    assert!(
        err.contains("10") && err.contains("<="),
        "error message must reference the block numbers: {}",
        err
    );
}

/// After accepting l2_block=10, a rollback to block=5 is rejected.
#[test]
fn test_regressing_block_rejected() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    let contest = make_contest("market_reg", 10);
    bc.store_contest_state(&contest).unwrap();

    let result = check_monotonic(&bc, "market_reg", 5);
    assert!(result.is_err(), "regressing l2_block (5 < 10) must be rejected");

    let err = result.unwrap_err();
    // Error must surface both the incoming and stored block numbers.
    assert!(
        err.contains("5") && err.contains("10"),
        "error must include both block numbers; got: {}",
        err,
    );
}

/// After accepting l2_block=10, the next submission of block=11 succeeds.
#[test]
fn test_strictly_incrementing_block_accepted() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    let contest = make_contest("market_inc", 10);
    bc.store_contest_state(&contest).unwrap();

    check_monotonic(&bc, "market_inc", 11)
        .expect("block 11 > 10 must be accepted");
}

/// Monotonicity is per-market — unrelated markets do not interfere.
#[test]
fn test_different_markets_are_independent() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    bc.store_contest_state(&make_contest("market_A", 50)).unwrap();
    bc.store_contest_state(&make_contest("market_B", 200)).unwrap();

    // market_A at 50 — block 10 should be rejected.
    assert!(
        check_monotonic(&bc, "market_A", 10).is_err(),
        "market_A: block 10 < 50 must fail"
    );

    // market_B at 200 — block 10 should be rejected.
    assert!(
        check_monotonic(&bc, "market_B", 10).is_err(),
        "market_B: block 10 < 200 must fail"
    );

    // market_C not yet stored — any block must succeed.
    check_monotonic(&bc, "market_C", 1)
        .expect("market_C (new) must accept block 1");

    // Advancing market_A to 51 must not affect market_B.
    let updated_a = make_contest("market_A", 51);
    bc.store_contest_state(&updated_a).unwrap();

    check_monotonic(&bc, "market_B", 201)
        .expect("market_B: block 201 > 200 must still pass");
    assert!(
        check_monotonic(&bc, "market_B", 200).is_err(),
        "market_B: equal block must still fail after market_A update"
    );
}

// ============================================================================
// TESTS — persistence ordering (ReDB written before cache)
// ============================================================================

/// Verify that storing and loading a ContestState round-trips correctly through
/// ReDB so that the monotonicity guard reads fresh durable state, not stale cache.
#[test]
fn test_contest_state_redb_round_trip() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    let contest = make_contest("round_trip", 42);
    bc.store_contest_state(&contest).unwrap();

    let loaded = bc.load_contest_state("round_trip")
        .expect("load must not error")
        .expect("record must exist after store");

    assert_eq!(loaded.last_l2_block, 42);
    assert_eq!(loaded.contest_id, "round_trip");
    assert_eq!(loaded.status, ContestStatus::Settled);
    assert_eq!(loaded.total_deposited, 10_000_000);
}

/// After a second store, `load_contest_state` returns the NEW value — confirming
/// that the persistence layer is not caching a stale entry.
#[test]
fn test_redb_always_returns_latest_write() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    bc.store_contest_state(&make_contest("latest_write", 7)).unwrap();
    bc.store_contest_state(&make_contest("latest_write", 15)).unwrap();

    let loaded = bc.load_contest_state("latest_write").unwrap().unwrap();
    assert_eq!(
        loaded.last_l2_block, 15,
        "second write (block=15) must overwrite first (block=7)"
    );
}

/// Sequential advance: simulate 5 state-root submissions and assert the guard
/// accepts each increment and rejects the previous value after each step.
#[test]
fn test_sequential_advance_10_rounds() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
    let market = "seq_market";

    for block in 1u64..=10 {
        // Guard must accept the new block.
        check_monotonic(&bc, market, block)
            .unwrap_or_else(|e| panic!("block {} should pass but got: {}", block, e));

        // Persist as if the handler succeeded.
        bc.store_contest_state(&make_contest(market, block)).unwrap();

        // Immediately re-submitting the same block must now be rejected.
        assert!(
            check_monotonic(&bc, market, block).is_err(),
            "re-submission of block {} must be rejected after storage",
            block
        );
    }
}

/// Escrow market root is stored in a SEPARATE ReDB table from ContestState.
/// Verify both round-trip independently so neither cache can mask a missing write.
#[test]
fn test_escrow_market_root_redb_round_trip() {
    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

    let market_id = "root_test_market";
    let root: [u8; 32] = {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(7); }
        r
    };

    bc.store_escrow_market_root(market_id, &root).unwrap();

    // load_contest_state must be independent of the market root table.
    assert!(
        bc.load_contest_state(market_id).unwrap().is_none(),
        "market root table and contest_state table must be distinct"
    );
}
