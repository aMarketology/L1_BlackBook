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

// Root-level modules
#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

// Re-exports
use social_mining::SocialMiningSystem;

// Use EnhancedBlockchain from protocol
use protocol::blockchain::EnhancedBlockchain;

// PoH Service imports - Proof of History for continuous timestamping
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule,
};

// Re-export core types from runtime (Borsh-enabled, two-lane architecture)
pub use runtime::core::TransactionType;

// ============================================================================
// PERSISTENCE
// ============================================================================

const BLOCKCHAIN_FILE: &str = "blockchain_data.json";
const SOCIAL_DATA_FILE: &str = "social_mining_data.json";

fn load_blockchain() -> EnhancedBlockchain {
    if let Ok(data) = fs::read_to_string(BLOCKCHAIN_FILE) {
        if let Ok(bc) = serde_json::from_str(&data) {
            println!("📂 Loaded blockchain from {}", BLOCKCHAIN_FILE);
            return bc;
        }
    }
    println!("🆕 Creating new blockchain with test accounts");
    let mut bc = EnhancedBlockchain::new();
    seed_test_accounts(&mut bc);
    bc
}

fn seed_test_accounts(bc: &mut EnhancedBlockchain) {
    // ========================================================================
    // TEST ACCOUNT INITIALIZATION (Development Only)
    // ========================================================================
    // In production, these accounts would be funded via real transactions.
    // For testing, we create "airdrop" transactions from Treasury.
    
    use crate::protocol::blockchain::TREASURY_ADDRESS;
    use crate::unified_wallet::strip_prefix;
    
    let alice = integration::unified_auth::get_alice_account();
    let bob = integration::unified_auth::get_bob_account();
    let dealer_address = integration::unified_auth::get_dealer_address();
    
    println!("🧪 Funding Test Accounts from Treasury (Development Mode):");
    println!("   ┌─────────────────────────────────────────────────────────┐");
    println!("   │ TREASURY → Test Account Airdrops                        │");
    println!("   └─────────────────────────────────────────────────────────┘");
    
    // Fund test accounts via Treasury transfers (proper blockchain transactions)
    let alice_hash = strip_prefix(&alice.address);
    let bob_hash = strip_prefix(&bob.address);
    let dealer_hash = strip_prefix(&dealer_address);
    
    // Create airdrop transactions from Treasury
    let _ = bc.create_transaction(
        TREASURY_ADDRESS.to_string(),
        alice_hash.clone(),
        alice.total_balance,
    );
    
    let _ = bc.create_transaction(
        TREASURY_ADDRESS.to_string(),
        bob_hash.clone(),
        bob.total_balance,
    );
    
    let _ = bc.create_transaction(
        TREASURY_ADDRESS.to_string(),
        dealer_hash.clone(),
        100000.0,  // 100k BB Dealer bankroll
    );
    
    // Mine the airdrop transactions
    bc.mine_pending_transactions("genesis_airdrop".to_string());
    
    println!("   💸 Alice:  {:>10} BB ← Treasury", alice.total_balance);
    println!("   💸 Bob:    {:>10} BB ← Treasury", bob.total_balance);
    println!("   💸 Dealer: {:>10} BB ← Treasury (House Bankroll)", 100000.0);
    
    let treasury_remaining = bc.get_balance(TREASURY_ADDRESS);
    println!("\n   📊 Treasury Remaining: {:.0} BB", treasury_remaining);
    println!("✅ Test accounts funded via Treasury transactions");
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
        if fs::write(SOCIAL_DATA_FILE, data).is_ok() {
            println!("💾 Saved social mining data to {}", SOCIAL_DATA_FILE);
        }
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
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║         LAYER1 BLOCKCHAIN V2 - Signature-Based Auth           ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║  Auth: Ed25519 Signatures (NO JWT!)                           ║");
    println!("║  PoH:  Continuous Proof of History Clock (Solana-style)       ║");
    println!("║  Arch: Two-Lane Transactions (Financial + Social)             ║");
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
    // INITIALIZE BLOCKCHAIN FIRST (needed by ServiceCoordinator)
    // ============================================================================
    let blockchain = Arc::new(Mutex::new(load_blockchain()));
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
    
    // Initialize MPC storage (for 2-of-2 threshold signing)
    let mpc_storage = integration::mpc_auth::MpcStorage::new();
    
    // Get full test account info
    let alice = integration::unified_auth::get_alice_account();
    let bob = integration::unified_auth::get_bob_account();
    
    // Get L1/L2 addresses using our unified wallet prefix system
    let alice_l1 = unified_wallet::to_l1_address(&alice.address);
    let alice_l2 = unified_wallet::to_l2_address(&alice.address);
    let bob_l1 = unified_wallet::to_l1_address(&bob.address);
    let bob_l2 = unified_wallet::to_l2_address(&bob.address);
    
    println!("\n🧪 FULL TEST ACCOUNTS (Alice & Bob) - L1/L2 PREFIXES:");
    println!("┌──────────────────────────────────────────────────────────────────┐");
    println!("│ 👛 UNIFIED WALLET: ALICE                                         │");
    println!("│ ─────────────────────────────────────────────────────────────── │");
    println!("│ Username: {:52} │", alice.username);
    println!("│ Email:    {:52} │", alice.email);
    println!("│ Public:   {}... │", &alice.public_key[..32]);
    println!("│ ─────────────────────────────────────────────────────────────── │");
    println!("│ 📍 L1 Address: {:48} │", alice_l1);
    println!("│    (Real balance - trading, withdrawals, transfers)            │");
    println!("│ 📍 L2 Address: {:48} │", alice_l2);
    println!("│    (Locked balance - betting sessions)                          │");
    println!("│ ─────────────────────────────────────────────────────────────── │");
    println!("│ 💰 L1 Balance:  {:46} │", format!("{} BB (available)", alice.l1_available));
    println!("│ 🔒 L1 Locked:   {:46} │", format!("{} BB (bridged to L2)", alice.l1_locked));
    println!("│ 🎰 L2 Balance:  {:46} │", format!("{} BB (betting)", alice.l2_balance));
    println!("├──────────────────────────────────────────────────────────────────┤");
    println!("│ 👛 UNIFIED WALLET: BOB                                           │");
    println!("│ ─────────────────────────────────────────────────────────────── │");
    println!("│ Username: {:52} │", bob.username);
    println!("│ Email:    {:52} │", bob.email);
    println!("│ Public:   {}... │", &bob.public_key[..32]);
    println!("│ ─────────────────────────────────────────────────────────────── │");
    println!("│ 📍 L1 Address: {:48} │", bob_l1);
    println!("│    (Real balance - trading, withdrawals, transfers)            │");
    println!("│ 📍 L2 Address: {:48} │", bob_l2);
    println!("│    (Locked balance - betting sessions)                          │");
    println!("│ ─────────────────────────────────────────────────────────────── │");
    println!("│ 💰 L1 Balance:  {:46} │", format!("{} BB (available)", bob.l1_available));
    println!("│ 🔒 L1 Locked:   {:46} │", format!("{} BB (bridged to L2)", bob.l1_locked));
    println!("│ 🎰 L2 Balance:  {:46} │", format!("{} BB (betting)", bob.l2_balance));
    println!("└──────────────────────────────────────────────────────────────────┘");
    println!("  💡 L1_ prefix = Real balance (can withdraw, trade, transfer)");
    println!("  💡 L2_ prefix = Locked for betting (just-in-time allocation)");
    println!("  🔄 Flow: L1_xxx → Lock → L2_xxx → Bet → Settle → L1_xxx");
    
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
    
    // Auth routes
    let keypair = routes_v2::auth::generate_keypair_route();
    let test_accounts = routes_v2::auth::test_accounts_route();
    let verify = routes_v2::auth::verify_signature_route();
    let profile = routes_v2::auth::profile_route(bc4);
    
    // Wallet routes
    let wallet_balance = routes_v2::wallet::balance_route(bc5);
    let wallet_info = routes_v2::wallet::wallet_info_route(bc6);
    
    // Transfer routes
    let transfer = routes_v2::transfer::transfer_route(blockchain.clone());
    let transactions = routes_v2::transfer::transactions_route(blockchain.clone());
    
    // Social routes
    let post = routes_v2::social::create_post_route(blockchain.clone(), ss1);
    let like = routes_v2::social::like_post_route(blockchain.clone(), ss2);
    let social_stats = routes_v2::social::social_stats_route(ss3);
    
    // Bridge routes (L1 ↔ L2)
    let bridge_initiate = routes_v2::bridge::bridge_initiate_route(blockchain.clone(), bridge_state.clone());
    let bridge_status = routes_v2::bridge::bridge_status_route(bridge_state.clone());
    let bridge_pending = routes_v2::bridge::bridge_pending_route(bridge_state.clone());
    let bridge_stats = routes_v2::bridge::bridge_stats_route(bridge_state.clone());
    let bridge_complete = routes_v2::bridge::bridge_complete_route(bridge_state.clone());
    let verify_sig = routes_v2::bridge::verify_signature_route();
    let relay = routes_v2::bridge::relay_action_route(blockchain.clone());
    
    // L2 Integration routes (wallet lookup, nonces, settlements)
    let wallet_by_user_id = routes_v2::bridge::wallet_by_user_id_route();
    let nonce = routes_v2::bridge::nonce_route(bridge_state.clone(), blockchain.clone());
    let settlement = routes_v2::bridge::settlement_route(bridge_state.clone(), blockchain.clone());
    let get_settlement = routes_v2::bridge::get_settlement_route(bridge_state.clone());
    
    // Settlement verification and release routes (NEW: Proper Escrow)
    let verify_settlement = routes_v2::bridge::verify_settlement_route(blockchain.clone(), bridge_state.clone());
    let release_tokens = routes_v2::bridge::release_tokens_route(blockchain.clone(), bridge_state.clone());
    
    // L2 → L1 Bridge routes (Withdraw, Merkle Settlements)
    let bridge_withdraw = routes_v2::bridge::withdraw_to_l1_route(blockchain.clone(), bridge_state.clone());
    let settle_root = routes_v2::bridge::post_settlement_root_route(bridge_state.clone(), blockchain.clone());
    let claim_settlement = routes_v2::bridge::claim_settlement_route(blockchain.clone(), bridge_state.clone());
    let list_roots = routes_v2::bridge::list_settlement_roots_route(bridge_state.clone());
    
    // Optimistic Execution routes (L2 Session Management) - LEGACY
    let session_start = routes_v2::bridge::start_session_route(blockchain.clone(), bridge_state.clone());
    let session_status = routes_v2::bridge::session_status_route(blockchain.clone(), bridge_state.clone());
    let session_settle = routes_v2::bridge::settle_session_route(blockchain.clone(), bridge_state.clone());
    let session_list = routes_v2::bridge::list_sessions_route(bridge_state.clone());
    
    // ═══════════════════════════════════════════════════════════════════════
    // CREDIT LINE ROUTES (Casino Bank Model)
    // ═══════════════════════════════════════════════════════════════════════
    let credit_approve = routes_v2::bridge::credit_approve_route(blockchain.clone(), bridge_state.clone());
    let credit_draw = routes_v2::bridge::credit_draw_route(blockchain.clone(), bridge_state.clone());
    let credit_settle = routes_v2::bridge::credit_settle_route(blockchain.clone(), bridge_state.clone());
    let credit_status = routes_v2::bridge::credit_status_route(blockchain.clone(), bridge_state.clone());
    
    // Markets routes (L2 market/event initial liquidity)
    let initial_liquidity = routes_v2::markets::initial_liquidity_route(blockchain.clone());
    
    // ═══════════════════════════════════════════════════════════════════════
    // UNIFIED WALLET: SESSION-BASED L2 INTEGRATION (THE RIGHT WAY)
    // ═══════════════════════════════════════════════════════════════════════
    // Only 3 endpoints needed:
    // 1. start-session  → Lock bankroll ONCE
    // 2. l1-balance     → Check real balance
    // 3. settle-session → Apply NET P&L ONCE
    // L2 handles all betting internally - NO per-bet L1 calls!
    let unified_start_session = routes_v2::bridge::start_session_unified_route(blockchain.clone());
    let unified_settle_session = routes_v2::bridge::settle_session_unified_route(blockchain.clone());
    let l1_balance_for_l2 = routes_v2::bridge::l1_balance_for_l2_route(blockchain.clone());
    
    // Admin routes (OPEN ACCESS - DEVELOPMENT ONLY)
    let admin_mint = routes_v2::admin::mint_tokens_route(blockchain.clone());
    
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
    
    // MPC routes (Multi-Party Computation for threshold signing)
    let mpc_routes = integration::mpc_auth::mpc_routes(mpc_storage.clone());
    
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
        .or(keypair)
        .or(test_accounts)
        .or(verify)
        .or(profile)
        .or(wallet_balance)
        .or(wallet_info)
        .or(transfer)
        .or(transactions)
        .or(post)
        .or(like)
        .or(social_stats)
        // Bridge routes
        .or(bridge_initiate)
        .or(bridge_status)
        .or(bridge_pending)
        .or(bridge_stats)
        .or(bridge_complete)
        .or(verify_sig)
        .or(relay)
        // L2 Integration routes
        .or(wallet_by_user_id)
        .or(nonce)
        .or(settlement)
        .or(get_settlement)
        // Settlement verification and release (Proper Escrow)
        .or(verify_settlement)
        .or(release_tokens)
        // L2 → L1 Bridge (Withdraw, Merkle Settlements)
        .or(bridge_withdraw)
        .or(settle_root)
        .or(claim_settlement)
        .or(list_roots)
        // Optimistic Execution (L2 Sessions) - LEGACY
        .or(session_start)
        .or(session_status)
        .or(session_settle)
        .or(session_list)
        // ═══════════════════════════════════════════════════════════════
        // CREDIT LINE (Casino Bank Model) - THE NEW WAY
        // One-time approval, auto-draw, session settlement
        // ═══════════════════════════════════════════════════════════════
        .or(credit_approve)
        .or(credit_draw)
        .or(credit_settle)
        .or(credit_status)
        // ═══════════════════════════════════════════════════════════════
        // UNIFIED WALLET (SESSION-BASED) - THE RIGHT WAY
        // Only 3 endpoints: start-session, l1-balance, settle-session
        // ═══════════════════════════════════════════════════════════════
        .or(unified_start_session)
        .or(unified_settle_session)
        .or(l1_balance_for_l2)
        // MPC routes (threshold signing)
        .or(mpc_routes)
        // Markets routes (L2 initial liquidity)
        .or(initial_liquidity)
        // Admin routes
        .or(admin_mint)
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
    
    // Autosave every 30 seconds (blockchain + social data)
    let bc_save = blockchain.clone();
    let social_save = social_system.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            
            // Clone data for saving (avoid holding locks across await)
            let bc_data = match bc_save.lock() {
                Ok(bc) => bc.clone(),
                Err(poisoned) => poisoned.into_inner().clone()
            };
            save_blockchain(&bc_data);
            
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
    println!("   │  THE DEALER (L1_DEALER00000001):                                │");
    println!("   │  • House bankroll account that pays winners instantly          │");
    println!("   │  • Collects from losers instantly                              │");
    println!("   │  • No escrow locking - funds move in real-time                 │");
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
    println!("   │  🧪 TEST ACCOUNTS:                                              │");
    println!("   │  • L1_ALICE000000001 (10,000 L1) - Test bettor                 │");
    println!("   │  • L1_BOB0000000001  (5,000 L1)  - Test bettor                 │");
    println!("   │  • L1_DEALER00000001 (100,000 L1) - House bankroll             │");
    println!("   │                                                                 │");
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
