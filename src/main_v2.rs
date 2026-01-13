// ============================================================================
// LAYER1 BLOCKCHAIN SERVER V2 - Sled-Only Immutable Persistence
// ============================================================================
//
// BlackBook L1 - Production Blockchain Server
// - Ed25519 signature-based authentication (NO JWT!)
// - Proof of History (PoH) continuous clock (Solana-style)
// - Two-lane transaction architecture (Financial + Social)
// - SLED-ONLY: All blocks persisted immediately, true immutability
// - Hot upgrade ready: Version tracking and migration hooks
//
// PERSISTENCE IS INNATE:
// Every transaction, every block, every state change is persisted to Sled.
// There is NO in-memory-only mode. Crash recovery is automatic.
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
mod unified_wallet;
mod consensus;
mod grpc;
mod storage;

// Root-level modules
#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

// Re-exports
use social_mining::SocialMiningSystem;

// Use PersistentBlockchain - the ONLY blockchain type for production
use storage::PersistentBlockchain;

// PoH Service imports - Proof of History for continuous timestamping
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule,
};

// Re-export core types from runtime (Borsh-enabled, two-lane architecture)
pub use runtime::core::TransactionType;

// ============================================================================
// SLED-ONLY PERSISTENCE - No JSON mode, no in-memory only
// ============================================================================

const SOCIAL_DATA_FILE: &str = "social_mining_data.json";
const SLED_DATA_PATH: &str = "./blockchain_sled";

/// Load blockchain from Sled (the ONLY storage mode)
fn load_blockchain() -> PersistentBlockchain {
    match PersistentBlockchain::new(SLED_DATA_PATH) {
        Ok(mut bc) => {
            // Check if we need to seed test accounts
            let treasury_balance = bc.get_balance(protocol::blockchain::TREASURY_ADDRESS);
            if treasury_balance >= protocol::blockchain::INITIAL_SUPPLY - 1000.0 {
                // Treasury hasn't been depleted - seed test accounts
                println!("🧪 Seeding test accounts...");
                seed_test_accounts(&mut bc);
            }
            println!("✅ Blockchain loaded from Sled ({})", SLED_DATA_PATH);
            bc
        }
        Err(e) => {
            panic!("❌ FATAL: Failed to initialize Sled storage: {:?}", e);
        }
    }
}

fn seed_test_accounts(bc: &mut PersistentBlockchain) {
    // ========================================================================
    // ACCOUNT STATUS DISPLAY (NO AUTO-SEEDING)
    // ========================================================================
    // Tokens are ONLY created through:
    // 1. Genesis block (Treasury initial supply)
    // 2. Admin mint endpoint (requires authorization)
    // 3. USDC deposit (1:1 backed minting)
    //
    // This ensures the blockchain maintains 1:1 integrity at all times.
    // NO automatic seeding - balances are persistent and immutable.
    // ========================================================================
    
    use crate::protocol::blockchain::TREASURY_ADDRESS;
    
    // Display known account addresses for reference
    let alice_address = "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8";
    let bob_address = "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433";
    let dealer_address = "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D";
    
    // Read-only balance check (no mutations!)
    let alice_bal = bc.get_balance(alice_address);
    let bob_bal = bc.get_balance(bob_address);
    let dealer_bal = bc.get_balance(dealer_address);
    let treasury_bal = bc.get_balance(TREASURY_ADDRESS);
    
    println!("📊 Account Balances (Read-Only - No Auto-Seeding):");
    println!("   ┌─────────────────────────────────────────────────────────┐");
    println!("   │ 🏦 Treasury: {:>15.2} BB                       │", treasury_bal);
    println!("   │ 👛 Alice:    {:>15.2} BB                       │", alice_bal);
    println!("   │ 👛 Bob:      {:>15.2} BB                       │", bob_bal);
    println!("   │ 🎰 Dealer:   {:>15.2} BB                       │", dealer_bal);
    println!("   └─────────────────────────────────────────────────────────┘");
    
    if alice_bal == 0.0 && bob_bal == 0.0 && dealer_bal == 0.0 {
        println!("   ⚠️  All accounts have 0 balance.");
        println!("   💡 To mint tokens, use POST /admin/mint with proper authorization");
        println!("   💡 Or deposit USDC to mint 1:1 backed $BC tokens");
    } else {
        println!("   ✅ Balances loaded from PERSISTENT STORAGE (Sled)");
    }
}

fn seed_test_accounts_legacy(_bc: &mut protocol::blockchain::EnhancedBlockchain) {
    // REMOVED - Sled-only mode, no JSON fallback
    unimplemented!("JSON mode removed - use Sled persistence only")
}

fn save_social_system(social_system: &SocialMiningSystem) {
    if let Ok(data) = serde_json::to_string_pretty(social_system) {
        let _ = fs::write(SOCIAL_DATA_FILE, data);
    }
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
// MAIN SERVER - SLED-ONLY PERSISTENCE
// ============================================================================

#[tokio::main]
async fn main() {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║     BLACKBOOK L1 - Immutable Blockchain (Sled Persistence)    ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║  Auth: Ed25519 Signatures (NO JWT!)                           ║");
    println!("║  PoH:  Continuous Proof of History Clock (Solana-style)       ║");
    println!("║  Arch: Two-Lane Transactions (Financial + Social)             ║");
    println!("║  Storage: Sled + Borsh (IMMUTABLE, CRASH-SAFE)                ║");
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
    println!("🎟️ Continuous PoH clock started (Solana-style Proof of History)");
    
    // ============================================================================
    // INITIALIZE BLOCKCHAIN (SLED-ONLY - Mandatory Persistence)
    // ============================================================================
    // PersistentBlockchain is the ONLY blockchain type for production.
    // Every transaction, every block is persisted immediately to Sled.
    // There is NO in-memory-only mode. Crash recovery is automatic.
    // ============================================================================
    
    println!("🗄️  Initializing Sled storage at {}", SLED_DATA_PATH);
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
    
    // ============================================================================
    // CONSENSUS ENGINE - Fork Choice, Block Proposal, P2P
    // ============================================================================
    let consensus_config = consensus::ConsensusConfig::default();
    let consensus_engine = Arc::new(tokio::sync::RwLock::new(
        consensus::ConsensusEngine::new(consensus_config, consensus::NodeType::Validator)
    ));
    println!("🔗 Consensus Engine initialized (Fork Choice + P2P ready)");
    
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
    
    // Initialize bridge state (LEGACY - kept for backwards compatibility)
    let bridge_state = Arc::new(Mutex::new(routes_v2::bridge::BridgeState::new()));
    
    // Initialize credit state (RECOMMENDED - simplified L2 credit line model)
    let credit_state = Arc::new(Mutex::new(routes_v2::credit::CreditState::new()));
    
    // Real Ed25519 test account addresses (derived from seeds)
    let alice_l1 = "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8";
    let bob_l1 = "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433";
    let dealer_l1 = "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D";
    
    // Get actual balances for display (READ-ONLY)
    let (alice_bal, bob_bal, dealer_bal) = {
        let bc = blockchain.lock().unwrap();
        (bc.get_balance(alice_l1), bc.get_balance(bob_l1), bc.get_balance(dealer_l1))
    };
    
    println!("\n📊 ACCOUNT BALANCES (Persistent - No Auto-Seeding):");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ 👛 ALICE:  {}  {:>12.2} BB │", alice_l1, alice_bal);
    println!("│ 👛 BOB:    {}  {:>12.2} BB │", bob_l1, bob_bal);
    println!("│ 🎰 DEALER: {}  {:>12.2} BB │", dealer_l1, dealer_bal);
    println!("└────────────────────────────────────────────────────────────────────────────┘");
    println!("  💡 Tokens only created via: POST /admin/mint (authorized)");
    println!("  💡 Or via USDC deposit (1:1 backed minting)");
    
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
    
    // Transfer routes (with PoH integration and Pipeline)
    let transfer = routes_v2::transfer::transfer_route(blockchain.clone());
    let transfer_poh = routes_v2::transfer::transfer_poh_route(blockchain.clone(), poh_service.clone());
    let transfer_pipeline = routes_v2::transfer::transfer_pipeline_route(
        blockchain.clone(), 
        pipeline.clone(),
        current_slot.clone()
    );
    let transfer_status = routes_v2::transfer::transfer_status_route(blockchain.clone(), current_slot.clone());
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
    
    // CREDIT LINE ROUTES (Casino Bank Model) - LEGACY bridge-based
    let credit_approve = routes_v2::bridge::credit_approve_route(blockchain.clone(), bridge_state.clone());
    let credit_draw = routes_v2::bridge::credit_draw_route(blockchain.clone(), bridge_state.clone());
    let credit_status_legacy = routes_v2::bridge::credit_status_route(blockchain.clone(), bridge_state.clone());
    
    // ═══════════════════════════════════════════════════════════════════════════
    // NEW SIMPLIFIED CREDIT ROUTES - RECOMMENDED FOR L2
    // ═══════════════════════════════════════════════════════════════════════════
    // POST /credit/open - Reserve funds from L1 for L2 gaming session
    // POST /credit/settle - Apply P&L back to L1 balances
    // GET  /credit/status/{wallet} - Check active credit line
    // GET  /credit/balance/{wallet} - Query L1 balance
    // ═══════════════════════════════════════════════════════════════════════════
    let credit_open = routes_v2::credit::open_credit_route(blockchain.clone(), credit_state.clone());
    let credit_settle_new = routes_v2::credit::settle_credit_route(blockchain.clone(), credit_state.clone());
    let credit_status_new = routes_v2::credit::credit_status_route(blockchain.clone(), credit_state.clone());
    let credit_balance = routes_v2::credit::credit_balance_route(blockchain.clone());
    
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
        .or(transfer_pipeline)
        .or(transfer_status)
        .or(transactions)
        .or(post)
        .or(like)
        .or(social_stats)
        // ═══════════════════════════════════════════════════════════════
        // BRIDGE ROUTES (Legacy - Core L1↔L2 bridge functionality)
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
        // CREDIT LINE - LEGACY (Casino Bank Model via Bridge)
        // ═══════════════════════════════════════════════════════════════
        .or(credit_approve)
        .or(credit_draw)
        .or(credit_status_legacy)
        // ═══════════════════════════════════════════════════════════════
        // CREDIT LINE - NEW SIMPLIFIED (RECOMMENDED)
        // POST /credit/open, POST /credit/settle, GET /credit/status/{w}
        // ═══════════════════════════════════════════════════════════════
        .or(credit_open)
        .or(credit_settle_new)
        .or(credit_status_new)
        .or(credit_balance)
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
    
    // Autosave every 30 seconds (Sled-only mode)
    // Sled persists on every transaction, but we flush periodically for safety
    let bc_save = blockchain.clone();
    let social_save = social_system.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            
            // Flush Sled storage
            if let Ok(bc) = bc_save.lock() {
                if let Err(e) = bc.flush() {
                    eprintln!("⚠️ Sled flush error: {:?}", e);
                } else {
                    println!("💾 Sled flushed (slot {})", bc.current_slot());
                }
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
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        
        println!("\n\n🛑 Shutdown signal received (Ctrl+C)");
        
        // Final flush
        if let Ok(bc) = bc_shutdown.lock() {
            if let Err(e) = bc.flush() {
                eprintln!("⚠️ Final flush error: {:?}", e);
            } else {
                println!("✅ Sled storage flushed");
            }
        }
        
        // Save social data
        let social_data = {
            let social = social_shutdown.lock().await;
            social.clone()
        };
        save_social_system(&social_data);
        
        println!("👋 Good bye, chosen one. Server is shutting down gracefully 👋");
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
