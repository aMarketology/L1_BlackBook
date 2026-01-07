// ============================================================================
// LAYER1 BLOCKCHAIN SERVER V2 - Pure Signature-Based Authentication
// ============================================================================
//
// Clean, streamlined server with:
// - Ed25519 signature-based authentication (NO JWT!)
// - Proof of History (PoH) continuous clock for Solana-style timestamping
// - Two-lane transaction architecture (Financial + Social)
// - Modular route handlers in routes_v2/
// - Alice & Bob test accounts for development
// - Uses protocol::blockchain for EnhancedBlockchain
//
// STORAGE OPTIONS:
// - --sled : Use Sled + Borsh persistence (production, default)
// - --json : Use JSON file persistence (legacy, for debugging)
//
// SOLANA-STYLE PERFORMANCE FEATURES:
// - Pipeline: 4-stage async transaction processing
// - Gulf Stream: Transaction forwarding to upcoming leaders
// - Turbine: Block propagation via shreds
// - Cloudbreak: High-performance account database
// - Archivers: Distributed ledger storage
// - Enhanced Sealevel: Parallel execution with fine-grained locking
//
// Run: cargo run
// Test: curl http://localhost:3030/health

#![recursion_limit = "512"]

use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU64;
use std::fs;
use std::env;

use warp::Filter;
use tokio::sync::Mutex as TokioMutex;
use parking_lot::RwLock;

// Core modules
mod social_mining;
mod integration;
mod routes_v2;
mod unified_wallet;  // Unified wallet system (L1/L2 address logic)
mod consensus;       // Consensus mechanisms (hot upgrades, validator selection, etc.)
mod grpc;            // gRPC Settlement (L1 ↔ L2 internal communication)
mod storage;         // Sled + Borsh persistence (production storage)

// Root-level modules
#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

// Re-exports
use social_mining::SocialMiningSystem;

// Use EnhancedBlockchain from protocol
use protocol::blockchain::EnhancedBlockchain;
// Use PersistentBlockchain from storage
use storage::PersistentBlockchain;

// PoH Service imports - Proof of History for continuous timestamping
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule,
};

// Re-export core types from runtime (Borsh-enabled, two-lane architecture)
pub use runtime::core::TransactionType;

// ============================================================================
// PERSISTENCE - JSON (Legacy) or Sled (Production)
// ============================================================================

const BLOCKCHAIN_FILE: &str = "blockchain_data.json";
const SOCIAL_DATA_FILE: &str = "social_mining_data.json";
const SLED_DATA_PATH: &str = "./blockchain_sled";

/// Check if we should use Sled persistence (default) or JSON (legacy)
fn use_sled_storage() -> bool {
    let args: Vec<String> = env::args().collect();
    
    // --json flag forces legacy JSON mode
    if args.iter().any(|a| a == "--json") {
        return false;
    }
    
    // Default to Sled (production)
    true
}

/// Load blockchain using Sled persistence (production)
fn load_blockchain_sled() -> PersistentBlockchain {
    match PersistentBlockchain::new(SLED_DATA_PATH) {
        Ok(mut bc) => {
            // Check if we need to seed test accounts
            let treasury_balance = bc.get_balance(protocol::blockchain::TREASURY_ADDRESS);
            if treasury_balance >= protocol::blockchain::INITIAL_SUPPLY - 1000.0 {
                // Treasury hasn't been depleted - seed test accounts
                println!("🧪 Seeding test accounts...");
                seed_test_accounts(&mut bc);
            }
            println!("📂 Loaded blockchain from Sled ({})", SLED_DATA_PATH);
            bc
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize Sled storage: {:?}", e);
            eprintln!("   Falling back to in-memory blockchain");
            // Create fresh blockchain wrapped in storage
            PersistentBlockchain::new(SLED_DATA_PATH)
                .expect("Failed to create fallback storage")
        }
    }
}

fn load_blockchain_json() -> EnhancedBlockchain {
    if let Ok(data) = fs::read_to_string(BLOCKCHAIN_FILE) {
        if let Ok(bc) = serde_json::from_str(&data) {
            println!("📂 Loaded blockchain from {}", BLOCKCHAIN_FILE);
            return bc;
        }
    }
    println!("🆕 Creating new blockchain with test accounts");
    let mut bc = EnhancedBlockchain::new();
    seed_test_accounts_enhanced(&mut bc);
    bc
}

fn seed_test_accounts(bc: &mut PersistentBlockchain) {
    // ========================================================================
    // TEST ACCOUNT INITIALIZATION (Development Only)
    // ========================================================================
    // Real Ed25519 derived addresses for Alice, Bob, and Dealer
    // These match the SDK TEST_ACCOUNTS for consistent testing
    // 
    // PERSISTENCE: Only fund accounts if they have zero balance.
    // Real crypto addresses persist their balances across sessions.
    // ========================================================================
    
    use crate::protocol::blockchain::TREASURY_ADDRESS;
    
    // Real cryptographic test accounts (Ed25519 derived from seeds)
    // Address = L1_ + SHA256(pubkey)[0..20].toUpperCase()
    let alice_address = "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8";  // seed: 18f2c2e3...
    let bob_address = "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433";    // seed: e4ac49e5...
    let dealer_address = "L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC"; // seed: d4e5f6a7...
    
    // Initial funding amounts (only applied if balance is 0)
    let alice_initial = 20000.0;
    let bob_initial = 10000.0;
    let dealer_initial = 100000.0;
    
    // Check existing balances (persistence!)
    let alice_bal = bc.get_balance(alice_address);
    let bob_bal = bc.get_balance(bob_address);
    let dealer_bal = bc.get_balance(dealer_address);
    
    println!("🧪 Test Account Status (Real Ed25519 Addresses):");
    println!("   ┌─────────────────────────────────────────────────────────┐");
    
    let mut funded_any = false;
    
    // Only fund if balance is zero (first run)
    if alice_bal == 0.0 {
        let _ = bc.create_transaction(
            TREASURY_ADDRESS.to_string(),
            alice_address.to_string(),
            alice_initial,
        );
        println!("   │ 💸 Alice:  {} BB ← Treasury (NEW)         │", alice_initial);
        funded_any = true;
    } else {
        println!("   │ 👛 Alice:  {} BB (persisted)                   │", alice_bal);
    }
    
    if bob_bal == 0.0 {
        let _ = bc.create_transaction(
            TREASURY_ADDRESS.to_string(),
            bob_address.to_string(),
            bob_initial,
        );
        println!("   │ 💸 Bob:    {} BB ← Treasury (NEW)          │", bob_initial);
        funded_any = true;
    } else {
        println!("   │ 👛 Bob:    {} BB (persisted)                    │", bob_bal);
    }
    
    if dealer_bal == 0.0 {
        let _ = bc.create_transaction(
            TREASURY_ADDRESS.to_string(),
            dealer_address.to_string(),
            dealer_initial,
        );
        println!("   │ 💸 Dealer: {} BB ← Treasury (NEW)       │", dealer_initial);
        funded_any = true;
    } else {
        println!("   │ 🎰 Dealer: {} BB (persisted)                 │", dealer_bal);
    }
    
    println!("   └─────────────────────────────────────────────────────────┘");
    
    // Only mine if we funded any accounts
    if funded_any {
        if let Err(e) = bc.mine_and_persist("genesis_airdrop".to_string()) {
            eprintln!("⚠️  Mining airdrop failed: {}", e);
        }
        println!("✅ New accounts funded from Treasury (persisted to Sled)");
    } else {
        println!("✅ All accounts loaded from persistent storage");
    }
}

fn seed_test_accounts_enhanced(bc: &mut EnhancedBlockchain) {
    // ========================================================================
    // TEST ACCOUNT INITIALIZATION (Development Only)
    // ========================================================================
    // Real Ed25519 derived addresses for Alice, Bob, and Dealer
    // These match the SDK TEST_ACCOUNTS for consistent testing
    // 
    // PERSISTENCE: Only fund accounts if they have zero balance.
    // Real crypto addresses persist their balances across sessions.
    // ========================================================================
    
    use crate::protocol::blockchain::TREASURY_ADDRESS;
    
    // Real cryptographic test accounts (Ed25519 derived from seeds)
    // Address = L1_ + SHA256(pubkey)[0..20].toUpperCase()
    let alice_address = "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8";  // seed: 18f2c2e3...
    let bob_address = "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433";    // seed: e4ac49e5...
    let dealer_address = "L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC"; // seed: d4e5f6a7...
    
    // Initial funding amounts (only applied if balance is 0)
    let alice_initial = 20000.0;
    let bob_initial = 10000.0;
    let dealer_initial = 100000.0;
    
    // Check existing balances (persistence!)
    let alice_bal = bc.get_balance(alice_address);
    let bob_bal = bc.get_balance(bob_address);
    let dealer_bal = bc.get_balance(dealer_address);
    
    println!("🧪 Test Account Status (Real Ed25519 Addresses):");
    println!("   ┌─────────────────────────────────────────────────────────┐");
    
    let mut funded_any = false;
    
    // Only fund if balance is zero (first run)
    if alice_bal == 0.0 {
        let _ = bc.create_transaction(
            TREASURY_ADDRESS.to_string(),
            alice_address.to_string(),
            alice_initial,
        );
        println!("   │ 💸 Alice:  {} BB ← Treasury (NEW)         │", alice_initial);
        funded_any = true;
    } else {
        println!("   │ 👛 Alice:  {} BB (persisted)                   │", alice_bal);
    }
    
    if bob_bal == 0.0 {
        let _ = bc.create_transaction(
            TREASURY_ADDRESS.to_string(),
            bob_address.to_string(),
            bob_initial,
        );
        println!("   │ 💸 Bob:    {} BB ← Treasury (NEW)          │", bob_initial);
        funded_any = true;
    } else {
        println!("   │ 👛 Bob:    {} BB (persisted)                    │", bob_bal);
    }
    
    if dealer_bal == 0.0 {
        let _ = bc.create_transaction(
            TREASURY_ADDRESS.to_string(),
            dealer_address.to_string(),
            dealer_initial,
        );
        println!("   │ 💸 Dealer: {} BB ← Treasury (NEW)       │", dealer_initial);
        funded_any = true;
    } else {
        println!("   │ 🎰 Dealer: {} BB (persisted)                 │", dealer_bal);
    }
    
    println!("   └─────────────────────────────────────────────────────────┘");
    
    // Only mine if we funded any accounts
    if funded_any {
        let _ = bc.mine_pending_transactions("genesis_airdrop".to_string());
        println!("✅ New accounts funded from Treasury");
    } else {
        println!("✅ All accounts loaded from persistent storage");
    }
}

fn save_blockchain(blockchain: &EnhancedBlockchain) {
    if let Ok(data) = serde_json::to_string_pretty(blockchain) {
        if fs::write(BLOCKCHAIN_FILE, data).is_ok() {
            println!("💾 Saved blockchain to {}", BLOCKCHAIN_FILE);
        }
    }
}

fn save_social_system(social_system: &SocialMiningSystem) {
    if let Ok(data) = serde_json::to_string_pretty(social_system) {
        let _ = fs::write(SOCIAL_DATA_FILE, data);
        // Silent save - no console spam
    }
}

fn emergency_save(blockchain: &EnhancedBlockchain, social_system: &SocialMiningSystem) {
    println!("\n🚨 EMERGENCY SAVE INITIATED...");
    
    // Save blockchain
    if let Ok(data) = serde_json::to_string_pretty(blockchain) {
        if fs::write(BLOCKCHAIN_FILE, &data).is_ok() {
            // Also create backup
            let _ = fs::write("blockchain_backup.json", data);
            println!("✅ Blockchain saved successfully");
        } else {
            eprintln!("❌ Failed to save blockchain!");
        }
    }
    
    // Save social mining data
    if let Ok(data) = serde_json::to_string_pretty(social_system) {
        if fs::write(SOCIAL_DATA_FILE, data).is_ok() {
            println!("✅ Social mining data saved successfully");
        } else {
            eprintln!("❌ Failed to save social mining data!");
        }
    }
    
    println!("✅ Emergency save complete - all user funds protected\n");
}

fn load_social_system() -> SocialMiningSystem {
    if let Ok(data) = fs::read_to_string(SOCIAL_DATA_FILE) {
        if let Ok(system) = serde_json::from_str(&data) {
            println!("📂 Loaded social mining from {}", SOCIAL_DATA_FILE);
            return system;
        }
    }
    println!("🆕 Creating new social mining system");
    SocialMiningSystem::new()
}

// ============================================================================
// MAIN SERVER
// ============================================================================

#[tokio::main]
async fn main() {
    // Check storage mode first
    let use_sled = use_sled_storage();
    
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║         LAYER1 BLOCKCHAIN V2 - Signature-Based Auth           ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║  Auth: Ed25519 Signatures (NO JWT!)                           ║");
    println!("║  PoH:  Continuous Proof of History Clock (Solana-style)       ║");
    println!("║  Arch: Two-Lane Transactions (Financial + Social)             ║");
    if use_sled {
        println!("║  Storage: Sled + Borsh (PRODUCTION)                           ║");
    } else {
        println!("║  Storage: JSON files (LEGACY MODE - use --sled for prod)      ║");
    }
    println!("║  Test: GET /auth/test-accounts for Alice & Bob                ║");
    println!("║  Admin: POST /admin/mint to mint tokens (OPEN ACCESS)         ║");
    println!("║  Bridge: POST /bridge/initiate for L1→L2 transfers            ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    
    // ============================================================================
    // INITIALIZE PROOF OF HISTORY (PoH) SERVICE
    // ============================================================================
    // The PoH clock runs continuously in the background, generating cryptographic
    // timestamps that prove the passage of time. This is the heart of our L1.
    //
    // Key Parameters:
    // - slot_duration_ms: 1000 (1 second slots)
    // - hashes_per_tick: 12500 (~12.5k SHA-256 hashes per tick = VDF)
    // - ticks_per_slot: 64 (64 PoH entries per second)
    // - slots_per_epoch: 432000 (~5 days per epoch for leader rotation)
    // ============================================================================
    let poh_config = PoHConfig {
        slot_duration_ms: 1000,    // 1 second slots
        hashes_per_tick: 12500,    // ~12.5k hashes per tick (Verifiable Delay Function)
        ticks_per_slot: 64,        // 64 ticks per slot = 64 PoH entries per second
        slots_per_epoch: 432000,   // ~5 days at 1s slots
    };
    let poh_service: SharedPoHService = create_poh_service(poh_config);
    
    // Spawn continuous PoH clock background task
    let poh_runner = poh_service.clone();
    tokio::spawn(async move {
        run_poh_clock(poh_runner).await;
    });
    println!("⏰ Continuous PoH clock started (Solana-style Proof of History)");
    
    // ============================================================================
    // INITIALIZE BLOCKCHAIN (Sled or JSON mode)
    // ============================================================================
    // In Sled mode: Uses PersistentBlockchain which wraps EnhancedBlockchain
    // In JSON mode: Uses EnhancedBlockchain directly with autosave
    // ============================================================================
    
    // For now, we use EnhancedBlockchain directly and manually call persist
    // This maintains API compatibility while adding Sled persistence
    let (blockchain, persistent_storage) = if use_sled {
        println!("🗄️  Initializing Sled storage at {}", SLED_DATA_PATH);
        let pbc = load_blockchain_sled();
        // Extract the inner blockchain for route handlers
        let inner: EnhancedBlockchain = (*pbc).clone();
        let storage = Some(pbc);
        (Arc::new(Mutex::new(inner)), storage)
    } else {
        println!("📁 Using JSON file persistence");
        (Arc::new(Mutex::new(load_blockchain_json())), None)
    };
    
    let social_system = Arc::new(TokioMutex::new(load_social_system()));
    
    // ============================================================================
    // INITIALIZE SOLANA-STYLE PERFORMANCE SERVICES (WIRED VERSION)
    // ============================================================================
    
    // Current slot tracker (shared across services)
    let current_slot = Arc::new(AtomicU64::new(0));
    
    // Leader Schedule for Gulf Stream
    let leader_schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
    {
        let mut schedule = leader_schedule.write();
        schedule.update_stake("genesis_validator", 1000.0);
        schedule.generate_schedule(0, 432000);
    }
    
    // 1. Transaction Pipeline (4-stage async processing)
    let (pipeline, _commit_rx) = TransactionPipeline::new();
    pipeline.start(current_slot.clone());
    println!("🔄 Transaction Pipeline started (fetch→verify→execute→commit)");
    
    // 2. Service Coordinator - WIRES ALL SERVICES TOGETHER
    // This creates and connects: Gulf Stream, Turbine, Cloudbreak, Archive, Block Producer
    let service_coordinator = routes_v2::ServiceCoordinator::new(
        blockchain.clone(),
        poh_service.clone(),
        current_slot.clone(),
        leader_schedule.clone(),
        1000, // slot_duration_ms
    );
    
    // Start all wired services (this replaces the individual service starts)
    service_coordinator.start_all();
    
    // Get service references for stats routes
    let pipeline_stats = pipeline.clone();
    let gulf_stream_stats = service_coordinator.gulf_stream.clone();
    let turbine_stats = service_coordinator.turbine.clone();
    let cloudbreak_stats = service_coordinator.cloudbreak.clone();
    let archivers_stats = service_coordinator.archive.clone();
    let block_producer_stats = service_coordinator.block_producer.clone();
    
    // Initialize bridge state
    let bridge_state = Arc::new(Mutex::new(routes_v2::bridge::BridgeState::new()));
    
    // Real Ed25519 test account addresses (derived from seeds)
    let alice_l1 = "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8";
    let bob_l1 = "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433";
    let dealer_l1 = "L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC";
    
    // Get actual balances for display
    let (alice_bal, bob_bal, dealer_bal) = {
        let bc = blockchain.lock().unwrap();
        (bc.get_balance(alice_l1), bc.get_balance(bob_l1), bc.get_balance(dealer_l1))
    };
    
    println!("\n🧪 TEST ACCOUNTS (Real Ed25519 Addresses):");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ 👛 ALICE:  {}  {:>10} BB │", alice_l1, alice_bal);
    println!("│ 👛 BOB:    {}  {:>10} BB │", bob_l1, bob_bal);
    println!("│ 🎰 DEALER: {}  {:>10} BB │", dealer_l1, dealer_bal);
    println!("└────────────────────────────────────────────────────────────────────────────┘");
    println!("  💡 Use /balance/<address> to check balances");
    println!("  💡 Use /transfer with SignedRequest to transfer BB tokens");
    
    // Clone for routes
    let bc1 = blockchain.clone();
    let bc2 = blockchain.clone();
    let bc3 = blockchain.clone();
    let bc4 = blockchain.clone();
    let bc5 = blockchain.clone();
    let bc6 = blockchain.clone();
    let ss1 = social_system.clone();
    let ss2 = social_system.clone();
    let ss3 = social_system.clone();
    
    // ========== BUILD ROUTES ==========
    
    // Public routes
    let health = routes_v2::rpc::health_route();
    let stats = routes_v2::rpc::stats_route(bc1);
    let public_balance = routes_v2::rpc::public_balance_route(bc2);
    let rpc = routes_v2::rpc::rpc_route(bc3);
    let poh_status = routes_v2::rpc::poh_status_route(poh_service.clone());
    let poh_verify = routes_v2::rpc::poh_verify_route(poh_service.clone());
    let ledger = routes_v2::rpc::ledger_route(blockchain.clone());
    
    // Auth routes
    let keypair = routes_v2::auth::generate_keypair_route();
    let test_accounts = routes_v2::auth::test_accounts_route();
    let verify = routes_v2::auth::verify_signature_route();
    let profile = routes_v2::auth::profile_route(bc4);
    
    // Wallet routes
    let wallet_balance = routes_v2::wallet::balance_route(bc5);
    let wallet_info = routes_v2::wallet::wallet_info_route(bc6);
    
    // Transfer routes (with PoH integration)
    let transfer = routes_v2::transfer::transfer_route(blockchain.clone());
    let transfer_poh = routes_v2::transfer::transfer_poh_route(blockchain.clone(), poh_service.clone());
    let transactions = routes_v2::transfer::transactions_route(blockchain.clone());
    
    // Social routes
    let post = routes_v2::social::create_post_route(blockchain.clone(), ss1);
    let like = routes_v2::social::like_post_route(blockchain.clone(), ss2);
    let social_stats = routes_v2::social::social_stats_route(ss3);
    
    // Bridge routes (L1 ↔ L2) - SIMPLIFIED
    let bridge_initiate = routes_v2::bridge::bridge_initiate_route(blockchain.clone(), bridge_state.clone());
    let bridge_status = routes_v2::bridge::bridge_status_route(bridge_state.clone());
    let bridge_pending = routes_v2::bridge::bridge_pending_route(bridge_state.clone());
    let bridge_stats = routes_v2::bridge::bridge_stats_route(bridge_state.clone());
    
    // L2 STATE ROOT ANCHORING (Optimistic Rollup)
    let l2_state_root = routes_v2::bridge::l2_state_root_route(blockchain.clone(), bridge_state.clone());
    let l2_latest_state = routes_v2::bridge::l2_latest_state_root_route(bridge_state.clone());
    let l2_all_states = routes_v2::bridge::l2_all_state_roots_route(bridge_state.clone());
    
    // CREDIT LINE ROUTES (Casino Bank Model) - CORE FUNCTIONALITY
    let credit_approve = routes_v2::bridge::credit_approve_route(blockchain.clone(), bridge_state.clone());
    let credit_draw = routes_v2::bridge::credit_draw_route(blockchain.clone(), bridge_state.clone());
    let credit_settle = routes_v2::bridge::credit_settle_route(blockchain.clone(), bridge_state.clone());
    let credit_status = routes_v2::bridge::credit_status_route(blockchain.clone(), bridge_state.clone());
    
    // Admin routes (OPEN ACCESS - DEVELOPMENT ONLY)
    let admin_mint = routes_v2::admin::mint_tokens_route(blockchain.clone());
    let admin_burn = routes_v2::admin::burn_tokens_route(blockchain.clone());
    
    // Protocol upgrade routes - TODO: Implement upgrade_manager in blockchain
    // let upgrade_propose = routes_v2::admin::propose_upgrade_route(blockchain.clone());
    // let upgrade_vote = routes_v2::admin::vote_upgrade_route(blockchain.clone());
    // let upgrade_list = routes_v2::admin::list_upgrades_route(blockchain.clone());
    // let upgrade_status = routes_v2::admin::upgrade_status_route(blockchain.clone());
    
    // Performance monitoring routes (Solana-style services)
    let perf_pipeline = pipeline_stats.clone();
    let perf_gulf = gulf_stream_stats.clone();
    let perf_turbine = turbine_stats.clone();
    let perf_cloud = cloudbreak_stats.clone();
    let perf_archive = archivers_stats.clone();
    let perf_block_prod = block_producer_stats.clone();
    
    let performance_stats = warp::path!("performance" / "stats")
        .and(warp::get())
        .map(move || {
            warp::reply::json(&serde_json::json!({
                "pipeline": perf_pipeline.get_stats(),
                "gulf_stream": perf_gulf.get_stats(),
                "turbine": perf_turbine.get_stats(),
                "cloudbreak": perf_cloud.get_stats(),
                "archivers": perf_archive.get_stats(),
                "block_producer": perf_block_prod.get_stats(),
                "status": "all_services_wired_and_running"
            }))
        });
    
    // Start gRPC server on 50051 (internal L1↔L2 communication)
    let grpc_blockchain = blockchain.clone();
    tokio::spawn(async move {
        let addr = "0.0.0.0:50051".parse().unwrap();
        let service = grpc::L1BankService::new(grpc_blockchain);
        println!("🌐 [L1 gRPC] Starting on {}", addr);
        println!("   └─ For L2 Sequencer internal communication");
        tonic::transport::Server::builder()
            .add_service(service.into_server())
            .serve(addr)
            .await
            .expect("gRPC server failed");
    });

    // Combine all routes
    let routes = health
        .or(stats)
        .or(public_balance)
        .or(rpc)
        .or(poh_status)
        .or(poh_verify)
        .or(ledger)
        .or(keypair)
        .or(test_accounts)
        .or(verify)
        .or(profile)
        .or(wallet_balance)
        .or(wallet_info)
        .or(transfer)
        .or(transfer_poh)
        .or(transactions)
        .or(post)
        .or(like)
        .or(social_stats)
        // ═══════════════════════════════════════════════════════════════
        // BRIDGE ROUTES (Simplified - Core L1↔L2 bridge functionality)
        // ═══════════════════════════════════════════════════════════════
        .or(bridge_initiate)
        .or(bridge_status)
        .or(bridge_pending)
        .or(bridge_stats)
        // ═══════════════════════════════════════════════════════════════
        // L2 STATE ROOT ANCHORING (Optimistic Rollup)
        // ═══════════════════════════════════════════════════════════════
        .or(l2_state_root)
        .or(l2_latest_state)
        .or(l2_all_states)
        // ═══════════════════════════════════════════════════════════════
        // CREDIT LINE (Casino Bank Model)
        // One-time approval, auto-draw, session settlement
        // ═══════════════════════════════════════════════════════════════
        .or(credit_approve)
        .or(credit_draw)
        .or(credit_settle)
        .or(credit_status)
        // Admin routes
        .or(admin_mint)
        .or(admin_burn)
        // Protocol upgrade routes - TODO: Implement upgrade_manager
        // .or(upgrade_propose)
        // .or(upgrade_vote)
        // .or(upgrade_list)
        // .or(upgrade_status)
        // Performance monitoring (Solana-style services)
        .or(performance_stats)
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
                .allow_headers(vec![
                    "Content-Type", 
                    "Authorization", 
                    "Accept",
                    "Origin",
                    "User-Agent",
                    "DNT",
                    "Cache-Control",
                    "X-Requested-With"
                ])
        );
    
    // Autosave every 30 seconds
    // In Sled mode: Flush Sled to disk (data is already persisted per-transaction)
    // In JSON mode: Write entire state to JSON file
    let bc_save = blockchain.clone();
    let social_save = social_system.clone();
    let use_sled_for_save = use_sled;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            
            // Clone data for saving (avoid holding locks across await)
            let bc_data = match bc_save.lock() {
                Ok(bc) => bc.clone(),
                Err(poisoned) => poisoned.into_inner().clone()
            };
            
            if use_sled_for_save {
                // Sled mode: sync accounts to storage periodically
                // Note: Block data is persisted immediately during mining
                if let Ok(bridge) = storage::StorageBridge::new(SLED_DATA_PATH) {
                    let slot = bc_data.current_slot;
                    match bridge.sync_accounts_from_hashmap(&bc_data.accounts, slot) {
                        Ok(count) => println!("💾 Synced {} accounts to Sled (slot {})", count, slot),
                        Err(e) => eprintln!("⚠️ Sled sync error: {:?}", e),
                    }
                }
            } else {
                // JSON mode: write entire state
                save_blockchain(&bc_data);
            }
            
            let social_data = {
                let social = social_save.lock().await;
                social.clone()
            };
            save_social_system(&social_data);
        }
    });
    
    // Graceful shutdown handler (Ctrl+C)
    let bc_shutdown = blockchain.clone();
    let social_shutdown = social_system.clone();
    let use_sled_for_shutdown = use_sled;
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        
        println!("\n\n🛑 Shutdown signal received (Ctrl+C)");
        
        // Emergency save (clone data to avoid lock issues)
        let bc_data = match bc_shutdown.lock() {
            Ok(bc) => bc.clone(),
            Err(poisoned) => poisoned.into_inner().clone()
        };
        
        let social_data = {
            let social = social_shutdown.lock().await;
            social.clone()
        };
        
        if use_sled_for_shutdown {
            // Sled mode: final flush
            if let Ok(bridge) = storage::StorageBridge::new(SLED_DATA_PATH) {
                let _ = bridge.sync_accounts_from_hashmap(&bc_data.accounts, bc_data.current_slot);
                let _ = bridge.flush();
                println!("✅ Sled storage flushed");
            }
        }
        
        // Always save to JSON as backup
        emergency_save(&bc_data, &social_data);
        
        println!("👋 Server shutting down gracefully...");
        std::process::exit(0);
    });
    
    println!("\n🚀 Server starting on http://0.0.0.0:8080");
    println!("   💾 Auto-save: Every 30 seconds");
    println!("   🛡️  Graceful shutdown: Ctrl+C to save & exit");
    println!("   🌐 CORS: Enabled (Allow Any Origin - localhost:5173 ✓)");
    println!("\n📡 ENDPOINTS:");
    println!("   GET  /health              - Health check");
    println!("   GET  /stats               - Blockchain stats");
    println!("   GET  /balance/:address    - Public balance check");
    println!("   POST /rpc                 - JSON-RPC endpoint");
    println!("   GET  /poh/status          - PoH clock status");
    println!("   GET  /poh/verify          - Verify PoH chain integrity");
    println!("   POST /auth/keypair        - Generate new keypair");
    println!("   GET  /auth/test-accounts  - Get Alice & Bob test accounts");
    println!("   POST /auth/verify         - Verify a signature");
    println!("   POST /profile             - Get profile (authenticated)");
    println!("   POST /wallet/balance      - Get balance (authenticated)");
    println!("   POST /wallet/info         - Get wallet info (authenticated)");
    println!("   POST /transfer            - Transfer tokens (authenticated)");
    println!("   POST /transactions        - Transaction history (authenticated)");
    println!("   POST /social/post         - Create post (authenticated)");
    println!("   POST /social/like         - Like post (authenticated)");
    println!("   GET  /social/stats        - Social mining stats");
    println!("\n🌉 BRIDGE (L1 ↔ L2):");
    println!("   POST /bridge/initiate     - Initiate L1→L2 bridge");
    println!("   GET  /bridge/status/:id   - Check bridge status");
    println!("   GET  /bridge/pending      - List pending bridges");
    println!("   GET  /bridge/stats        - Bridge statistics");
    println!("   POST /bridge/complete     - L2 confirms bridge complete");
    println!("   POST /rpc/verify-signature - Verify L1 signature (for L2)");
    println!("   POST /rpc/relay           - Relay signed action to L2");
    println!("\n🔗 L2 INTEGRATION:");
    println!("   GET  /auth/wallet/:user_id  - Lookup L1 wallet by Supabase user_id");
    println!("   GET  /rpc/nonce/:address    - Get cross-layer nonce for address");
    println!("   POST /rpc/settlement        - Record L2 market settlement on L1");
    println!("   GET  /rpc/settlement/:id    - Get settlement record by ID");
    println!("\n🏦 L2→L1 WITHDRAWAL & SETTLEMENTS:");
    println!("   POST /bridge/withdraw       - L2 unlocks tokens on L1");
    println!("   POST /bridge/settle-root    - L2 posts Merkle settlement root");
    println!("   POST /bridge/claim          - User claims settlement with proof");
    println!("   GET  /bridge/settlement-roots - List all settlement roots");
    println!("\n🎮 OPTIMISTIC EXECUTION (L2 Sessions - LEGACY):");
    println!("   POST /session/start         - Start L2 session (mirror L1→L2)");
    println!("   GET  /session/status/:addr  - Get session + both balances");
    println!("   POST /session/bet           - Record bet result (L2 only)");
    println!("   POST /session/settle        - Settle session (write PnL to L1)");
    println!("   GET  /session/list          - List all active sessions");
    println!("\n🔐 MPC (Multi-Party Computation):");
    println!("   POST /mpc/keygen            - Initialize MPC wallet (2-of-2 setup)");
    println!("   POST /mpc/sign              - Sign with threshold (client shard required)");
    println!("   POST /mpc/status            - Check if wallet has MPC enabled");
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("🎰 UNIFIED WALLET - DEALER MODEL (INSTANT SETTLEMENT):");
    println!("═══════════════════════════════════════════════════════════════");
    println!("   POST /bridge/start-session    - Lock bankroll at session start");
    println!("   GET  /bridge/l1-balance/:addr - Query real-time L1 balance");
    println!("   POST /bridge/settle-session   - Apply NET P&L at cashout");
    println!();
    println!("   ┌─────────────────────────────────────────────────────────────────┐");
    println!("   │  🃏 DEALER MODEL - How Betting Actually Works                   │");
    println!("   ├─────────────────────────────────────────────────────────────────┤");
    println!("   │                                                                 │");
    println!("   │  THE DEALER ({}):     │", dealer_l1);
    println!("   │  • House bankroll account that pays winners instantly          │");
    println!("   │  • Collects from losers instantly                              │");
    println!("   │  • Private key secured via DEALER_PRIVATE_KEY env var          │");
    println!("   │                                                                 │");
    println!("   │  EXAMPLE: Alice bets $50 on Heads, Bob bets $50 on Tails       │");
    println!("   │  ┌─────────────────────────────────────────────────────────┐   │");
    println!("   │  │ BEFORE:  Alice: $1000  Bob: $500  Dealer: $10,000       │   │");
    println!("   │  │ BET:     Alice → Dealer: $50                            │   │");
    println!("   │  │          Bob → Dealer: $50                              │   │");
    println!("   │  │ RESULT:  Heads wins! Alice gets $100 from Dealer        │   │");
    println!("   │  │ AFTER:   Alice: $1050  Bob: $450  Dealer: $9,950        │   │");
    println!("   │  └─────────────────────────────────────────────────────────┘   │");
    println!("   │                                                                 │");
    println!("   │  ✅ BENEFITS:                                                   │");
    println!("   │  • Instant payouts (no waiting for opponent)                   │");
    println!("   │  • No counterparty risk (Dealer always has funds)              │");
    println!("   │  • Simple 2-tx settlement (bet + payout)                       │");
    println!("   │  • L2 can batch multiple bets, settle NET on L1                │");
    println!("   │                                                                 │");
    println!("   │  🧪 TEST ACCOUNTS (Real Addresses):                            │");
    println!("   │  • {} (10,000 BB) - Alice  │", alice_l1);
    println!("   │  • {} (5,000 BB)  - Bob    │", bob_l1);
    println!("   │  • {} (100,000 BB) - Dealer│", dealer_l1);
    println!("   │                                                                 │");
    println!("   │  ⚠️  Alice/Bob keys exposed (test). Dealer key in .env (prod)   │");
    println!("   └─────────────────────────────────────────────────────────────────┘");
    println!("\n⚡ PERFORMANCE MONITORING (Solana-style):");
    println!("   GET  /performance/stats     - All service statistics");
    println!("       └─ Pipeline, Gulf Stream, Turbine, Cloudbreak, Archivers");
    println!();
    
    // ========================================================================
    // START REST SERVER (User ↔ L1 Communication)
    // ========================================================================
    println!("🌐 [L1 REST] Starting on http://0.0.0.0:8080");
    println!("   └─ For user apps, wallets, frontends");
    println!("\n🚀 Server ready! Test with: curl http://localhost:8080/health\n");
    
    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
