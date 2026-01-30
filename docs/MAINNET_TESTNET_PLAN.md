# 🌐 BlackBook L1 - Mainnet & Testnet Architecture Plan

> **Document Version**: 1.0  
> **Created**: January 27, 2026  
> **Status**: Planning Phase  
> **Target Implementation**: February 2026

---

## Table of Contents
1. [Overview](#overview)
2. [Network Architecture](#network-architecture)
3. [Chain ID System](#chain-id-system)
4. [Hot Upgrades System](#hot-upgrades-system)
5. [Environment Configuration](#environment-configuration)
6. [Database Separation](#database-separation)
7. [Implementation Plan](#implementation-plan)
8. [Migration Strategy](#migration-strategy)

---

## Overview

### Goals
1. **Parallel Networks**: Run mainnet and testnet simultaneously
2. **Hot Upgrades**: Deploy protocol changes without hard forks
3. **Environment Isolation**: Complete separation of state, databases, and configs
4. **SDK Support**: Single SDK that works with any network
5. **Zero Downtime**: Upgrades happen while chain is running

### Network Types

| Network | Purpose | Chain ID | Token | USDC Backing |
|---------|---------|----------|-------|--------------|
| **Mainnet** | Production (real value) | `0x01` | BB | Required |
| **Testnet** | Development/Testing | `0x10` | tBB | None (faucet) |
| **Devnet** | Local development | `0xFF` | dBB | None (auto-mint) |

---

## Network Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           BLACKBOOK NETWORK              │
                    └─────────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
         ▼                             ▼                             ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│    MAINNET      │         │    TESTNET      │         │    DEVNET       │
│    (0x01)       │         │    (0x10)       │         │    (0xFF)       │
├─────────────────┤         ├─────────────────┤         ├─────────────────┤
│ Port: 8080      │         │ Port: 8081      │         │ Port: 8082      │
│ gRPC: 50051     │         │ gRPC: 50052     │         │ gRPC: 50053     │
│                 │         │                 │         │                 │
│ DB: /mainnet    │         │ DB: /testnet    │         │ DB: /devnet     │
│                 │         │                 │         │                 │
│ USDC Required ✓ │         │ Faucet Only     │         │ Auto-mint       │
│ Real Value ✓    │         │ Test Value      │         │ Dev Value       │
└─────────────────┘         └─────────────────┘         └─────────────────┘
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
                    ┌─────────────────────────────────────────┐
                    │           SHARED COMPONENTS              │
                    ├─────────────────────────────────────────┤
                    │  • Protocol Binary (hot upgradeable)     │
                    │  • SDK (network-aware)                   │
                    │  • Supabase (separate projects)          │
                    │  • Monitoring (Grafana/Prometheus)       │
                    └─────────────────────────────────────────┘
```

---

## Chain ID System

### Extended Chain IDs

```rust
// src/integration/unified_auth.rs - Extended Chain IDs

/// Network Chain IDs - Used for domain separation and replay protection
pub mod chain_ids {
    /// Mainnet L1 - Production (real value)
    pub const MAINNET_L1: u8 = 0x01;
    
    /// Mainnet L2 - Production bridge
    pub const MAINNET_L2: u8 = 0x02;
    
    /// Testnet L1 - Public testing
    pub const TESTNET_L1: u8 = 0x10;
    
    /// Testnet L2 - Testing bridge
    pub const TESTNET_L2: u8 = 0x11;
    
    /// Devnet L1 - Local development
    pub const DEVNET_L1: u8 = 0xFF;
    
    /// Devnet L2 - Local development bridge  
    pub const DEVNET_L2: u8 = 0xFE;
}

/// Network configuration
pub struct NetworkConfig {
    pub chain_id: u8,
    pub name: &'static str,
    pub http_port: u16,
    pub grpc_port: u16,
    pub db_path: &'static str,
    pub requires_usdc_backing: bool,
    pub faucet_enabled: bool,
    pub max_faucet_amount: f64,
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        Self {
            chain_id: chain_ids::MAINNET_L1,
            name: "BlackBook Mainnet",
            http_port: 8080,
            grpc_port: 50051,
            db_path: "./blockchain_data/mainnet",
            requires_usdc_backing: true,
            faucet_enabled: false,
            max_faucet_amount: 0.0,
        }
    }
    
    pub fn testnet() -> Self {
        Self {
            chain_id: chain_ids::TESTNET_L1,
            name: "BlackBook Testnet",
            http_port: 8081,
            grpc_port: 50052,
            db_path: "./blockchain_data/testnet",
            requires_usdc_backing: false,
            faucet_enabled: true,
            max_faucet_amount: 10000.0, // 10k tBB per request
        }
    }
    
    pub fn devnet() -> Self {
        Self {
            chain_id: chain_ids::DEVNET_L1,
            name: "BlackBook Devnet",
            http_port: 8082,
            grpc_port: 50053,
            db_path: "./blockchain_data/devnet",
            requires_usdc_backing: false,
            faucet_enabled: true,
            max_faucet_amount: 1000000.0, // 1M dBB (unlimited for dev)
        }
    }
}
```

### Domain Separation (Prevents Cross-Network Replay)

```
Mainnet Signature:   BLACKBOOK_L1/transfer\n{hash}\n{ts}\n{nonce}
Testnet Signature:   BLACKBOOK_L16/transfer\n{hash}\n{ts}\n{nonce}  (0x10 = 16)
Devnet Signature:    BLACKBOOK_L255/transfer\n{hash}\n{ts}\n{nonce} (0xFF = 255)

✅ A testnet transaction CANNOT replay on mainnet
✅ A mainnet transaction CANNOT replay on testnet
```

---

## Hot Upgrades System

### Philosophy

**Traditional Blockchain Upgrades:**
```
1. Announce upgrade → 2. Coordinate validators → 3. Hard fork at block X → 4. Pray nothing breaks
```

**BlackBook Hot Upgrades:**
```
1. Deploy new version → 2. Activate via admin → 3. Protocol switches → 4. Zero downtime
```

### Implementation Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     HOT UPGRADES SYSTEM                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    VERSION MANAGER                           │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │  current_version: "3.1.0"                                    │   │
│  │  pending_upgrade: Some("3.2.0")                              │   │
│  │  activation_slot: 1000000                                    │   │
│  │  rollback_enabled: true                                      │   │
│  │  upgrade_history: [("3.0.0", slot_500000), ...]             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  PROTOCOL HANDLERS                           │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │                                                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │   │
│  │  │ Transfer    │  │ Bridge      │  │ Consensus   │         │   │
│  │  │ v3.1.0      │  │ v3.1.0      │  │ v3.1.0      │         │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘         │   │
│  │        ▼                ▼                ▼                  │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │   │
│  │  │ Transfer    │  │ Bridge      │  │ Consensus   │         │   │
│  │  │ v3.2.0      │  │ v3.2.0      │  │ v3.2.0      │         │   │
│  │  │ (pending)   │  │ (pending)   │  │ (pending)   │         │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘         │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol Version Traits

```rust
// src/upgrades/mod.rs

use std::sync::Arc;
use parking_lot::RwLock;

/// Protocol version identifier
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }
    
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 { return None; }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }
}

/// Trait for hot-upgradeable protocol handlers
pub trait ProtocolHandler: Send + Sync {
    fn version(&self) -> ProtocolVersion;
    fn name(&self) -> &'static str;
    
    /// Called when this version becomes active
    fn on_activate(&self, from_version: Option<&ProtocolVersion>) -> Result<(), String>;
    
    /// Called when this version is deactivated (rollback or upgrade)
    fn on_deactivate(&self) -> Result<(), String>;
}

/// Transfer handler trait (versioned)
pub trait TransferHandler: ProtocolHandler {
    fn validate_transfer(&self, from: &str, to: &str, amount: f64) -> Result<(), String>;
    fn execute_transfer(&self, from: &str, to: &str, amount: f64) -> Result<String, String>;
    fn get_fee(&self, amount: f64) -> f64;
}

/// Bridge handler trait (versioned)
pub trait BridgeHandler: ProtocolHandler {
    fn initiate_bridge(&self, wallet: &str, amount: f64, target: &str) -> Result<String, String>;
    fn complete_bridge(&self, lock_id: &str) -> Result<(), String>;
    fn challenge_period_slots(&self) -> u64;
}
```

### Version Manager

```rust
// src/upgrades/version_manager.rs

pub struct VersionManager {
    /// Current active protocol version
    current_version: RwLock<ProtocolVersion>,
    
    /// Pending upgrade (if scheduled)
    pending_upgrade: RwLock<Option<PendingUpgrade>>,
    
    /// History of upgrades
    upgrade_history: RwLock<Vec<UpgradeRecord>>,
    
    /// Protocol handlers by version
    handlers: RwLock<HashMap<ProtocolVersion, Arc<dyn ProtocolHandler>>>,
    
    /// Rollback capability
    previous_handlers: RwLock<Option<Arc<dyn ProtocolHandler>>>,
}

#[derive(Clone, Debug)]
pub struct PendingUpgrade {
    pub to_version: ProtocolVersion,
    pub activation_slot: u64,
    pub scheduled_at: u64,
    pub scheduled_by: String,  // Admin pubkey
    pub changelog: String,
}

#[derive(Clone, Debug)]
pub struct UpgradeRecord {
    pub from_version: ProtocolVersion,
    pub to_version: ProtocolVersion,
    pub activated_at_slot: u64,
    pub activated_at_time: u64,
}

impl VersionManager {
    pub fn new(initial_version: ProtocolVersion) -> Self {
        Self {
            current_version: RwLock::new(initial_version),
            pending_upgrade: RwLock::new(None),
            upgrade_history: RwLock::new(Vec::new()),
            handlers: RwLock::new(HashMap::new()),
            previous_handlers: RwLock::new(None),
        }
    }
    
    /// Schedule an upgrade for a future slot
    pub fn schedule_upgrade(
        &self,
        to_version: ProtocolVersion,
        activation_slot: u64,
        admin_pubkey: &str,
        changelog: &str,
    ) -> Result<(), String> {
        let current = self.current_version.read().clone();
        
        // Validate: new version must be higher
        if to_version <= current {
            return Err(format!(
                "Cannot downgrade: {} -> {}", 
                current.to_string(), 
                to_version.to_string()
            ));
        }
        
        // Validate: handler exists for new version
        if !self.handlers.read().contains_key(&to_version) {
            return Err(format!("No handler registered for {}", to_version.to_string()));
        }
        
        *self.pending_upgrade.write() = Some(PendingUpgrade {
            to_version,
            activation_slot,
            scheduled_at: current_timestamp(),
            scheduled_by: admin_pubkey.to_string(),
            changelog: changelog.to_string(),
        });
        
        Ok(())
    }
    
    /// Check and apply pending upgrade (called every slot)
    pub fn check_pending_upgrade(&self, current_slot: u64) -> Option<ProtocolVersion> {
        let pending = self.pending_upgrade.read().clone();
        
        if let Some(upgrade) = pending {
            if current_slot >= upgrade.activation_slot {
                // Time to upgrade!
                return self.apply_upgrade(&upgrade.to_version).ok();
            }
        }
        
        None
    }
    
    /// Emergency rollback to previous version
    pub fn rollback(&self) -> Result<ProtocolVersion, String> {
        let previous = self.previous_handlers.read().clone()
            .ok_or("No previous version to rollback to")?;
        
        let prev_version = previous.version();
        
        // Deactivate current
        if let Some(current) = self.handlers.read().get(&*self.current_version.read()) {
            current.on_deactivate()?;
        }
        
        // Reactivate previous
        previous.on_activate(Some(&*self.current_version.read()))?;
        
        // Update state
        *self.current_version.write() = prev_version.clone();
        
        Ok(prev_version)
    }
    
    fn apply_upgrade(&self, to_version: &ProtocolVersion) -> Result<ProtocolVersion, String> {
        let handlers = self.handlers.read();
        let new_handler = handlers.get(to_version)
            .ok_or(format!("Handler not found for {}", to_version.to_string()))?;
        
        let current = self.current_version.read().clone();
        
        // Store current as rollback option
        if let Some(current_handler) = handlers.get(&current) {
            *self.previous_handlers.write() = Some(current_handler.clone());
        }
        
        // Deactivate current
        if let Some(current_handler) = handlers.get(&current) {
            current_handler.on_deactivate()?;
        }
        
        // Activate new
        new_handler.on_activate(Some(&current))?;
        
        // Update version
        *self.current_version.write() = to_version.clone();
        
        // Record upgrade
        self.upgrade_history.write().push(UpgradeRecord {
            from_version: current,
            to_version: to_version.clone(),
            activated_at_slot: 0, // Fill in caller
            activated_at_time: current_timestamp(),
        });
        
        // Clear pending
        *self.pending_upgrade.write() = None;
        
        Ok(to_version.clone())
    }
}
```

### Hot Upgrade API Endpoints

```rust
// Add to main_v3.rs

/// GET /upgrades/status - Current version and pending upgrades
async fn upgrades_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let vm = &state.version_manager;
    let current = vm.current_version();
    let pending = vm.pending_upgrade();
    let history = vm.upgrade_history();
    
    Json(serde_json::json!({
        "current_version": current.to_string(),
        "pending_upgrade": pending.map(|p| serde_json::json!({
            "to_version": p.to_version.to_string(),
            "activation_slot": p.activation_slot,
            "slots_remaining": p.activation_slot.saturating_sub(state.current_slot()),
            "scheduled_by": p.scheduled_by,
            "changelog": p.changelog
        })),
        "upgrade_history": history.iter().map(|r| serde_json::json!({
            "from": r.from_version.to_string(),
            "to": r.to_version.to_string(),
            "slot": r.activated_at_slot
        })).collect::<Vec<_>>()
    }))
}

/// POST /admin/upgrades/schedule - Schedule a protocol upgrade (admin only)
#[derive(Deserialize)]
struct ScheduleUpgradeRequest {
    to_version: String,
    activation_slot: u64,
    changelog: String,
    admin_signature: String, // Ed25519 signature
}

async fn schedule_upgrade_handler(
    State(state): State<AppState>,
    Json(req): Json<ScheduleUpgradeRequest>,
) -> impl IntoResponse {
    // 1. Verify admin signature
    // 2. Parse version
    // 3. Schedule upgrade
    
    let version = ProtocolVersion::parse(&req.to_version)
        .ok_or("Invalid version format")?;
    
    state.version_manager.schedule_upgrade(
        version,
        req.activation_slot,
        "admin", // Derived from signature
        &req.changelog
    )?;
    
    Json(serde_json::json!({
        "success": true,
        "scheduled_version": req.to_version,
        "activation_slot": req.activation_slot
    }))
}

/// POST /admin/upgrades/rollback - Emergency rollback (admin only)
async fn rollback_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.version_manager.rollback() {
        Ok(version) => Json(serde_json::json!({
            "success": true,
            "rolled_back_to": version.to_string()
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        }))
    }
}
```

---

## Environment Configuration

### Network Selection via Environment

```bash
# .env.mainnet
NETWORK=mainnet
CHAIN_ID=0x01
HTTP_PORT=8080
GRPC_PORT=50051
DB_PATH=./blockchain_data/mainnet
REQUIRES_USDC=true
FAUCET_ENABLED=false
LOG_LEVEL=info

# Supabase (Mainnet)
SUPABASE_URL=https://mainnet.supabase.co
SUPABASE_ANON_KEY=mainnet_key

# USDC Oracle
USDC_ORACLE_URL=https://api.circle.com/v1
```

```bash
# .env.testnet
NETWORK=testnet
CHAIN_ID=0x10
HTTP_PORT=8081
GRPC_PORT=50052
DB_PATH=./blockchain_data/testnet
REQUIRES_USDC=false
FAUCET_ENABLED=true
FAUCET_MAX_AMOUNT=10000
LOG_LEVEL=debug

# Supabase (Testnet)
SUPABASE_URL=https://testnet.supabase.co
SUPABASE_ANON_KEY=testnet_key
```

### Runtime Configuration Loading

```rust
// src/config.rs

use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub network: NetworkType,
    pub chain_id: u8,
    pub http_port: u16,
    pub grpc_port: u16,
    pub db_path: String,
    pub requires_usdc: bool,
    pub faucet_enabled: bool,
    pub faucet_max_amount: f64,
    pub supabase_url: String,
    pub supabase_key: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Devnet,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let network = match env::var("NETWORK").unwrap_or_default().as_str() {
            "mainnet" => NetworkType::Mainnet,
            "testnet" => NetworkType::Testnet,
            "devnet" | _ => NetworkType::Devnet,
        };
        
        Ok(Self {
            network: network.clone(),
            chain_id: parse_hex_env("CHAIN_ID", match network {
                NetworkType::Mainnet => 0x01,
                NetworkType::Testnet => 0x10,
                NetworkType::Devnet => 0xFF,
            }),
            http_port: env::var("HTTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            grpc_port: env::var("GRPC_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50051),
            db_path: env::var("DB_PATH")
                .unwrap_or_else(|_| "./blockchain_data".to_string()),
            requires_usdc: env::var("REQUIRES_USDC")
                .map(|s| s == "true")
                .unwrap_or(false),
            faucet_enabled: env::var("FAUCET_ENABLED")
                .map(|s| s == "true")
                .unwrap_or(true),
            faucet_max_amount: env::var("FAUCET_MAX_AMOUNT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000000.0),
            supabase_url: env::var("SUPABASE_URL")
                .unwrap_or_default(),
            supabase_key: env::var("SUPABASE_ANON_KEY")
                .unwrap_or_default(),
        })
    }
}
```

---

## Database Separation

### Directory Structure

```
blockchain_data/
├── mainnet/
│   ├── blockchain.redb          # ReDB main database
│   ├── blocks/                   # Block archive
│   ├── state_roots/              # Merkle state roots
│   └── backups/                  # Daily backups
│
├── testnet/
│   ├── blockchain.redb
│   ├── blocks/
│   ├── state_roots/
│   └── backups/
│
└── devnet/
    ├── blockchain.redb
    ├── blocks/
    └── state_roots/
```

### Genesis Blocks

```rust
// src/genesis.rs

pub fn create_genesis(network: &NetworkType) -> GenesisBlock {
    match network {
        NetworkType::Mainnet => GenesisBlock {
            chain_id: 0x01,
            timestamp: 1738195200, // Jan 30, 2026 00:00:00 UTC
            initial_supply: 0.0, // All BB must be backed by USDC
            initial_accounts: vec![
                // Treasury (0 balance, receives USDC-backed mints)
                ("L1_TREASURY_MAINNET", 0.0),
            ],
            genesis_hash: "BLACKBOOK_MAINNET_GENESIS_V1",
            protocol_version: ProtocolVersion::new(3, 0, 0),
        },
        
        NetworkType::Testnet => GenesisBlock {
            chain_id: 0x10,
            timestamp: 1738108800, // Jan 29, 2026 00:00:00 UTC
            initial_supply: 100_000_000.0, // 100M tBB for testing
            initial_accounts: vec![
                ("L1_FAUCET_TESTNET", 100_000_000.0),
            ],
            genesis_hash: "BLACKBOOK_TESTNET_GENESIS_V1",
            protocol_version: ProtocolVersion::new(3, 0, 0),
        },
        
        NetworkType::Devnet => GenesisBlock {
            chain_id: 0xFF,
            timestamp: 0, // Epoch (for reproducible tests)
            initial_supply: 1_000_000_000.0, // 1B dBB
            initial_accounts: vec![
                ("L1_FAUCET_DEVNET", 500_000_000.0),
                (ALICE_L1, 1_000_000.0),
                (BOB_L1, 1_000_000.0),
                (DEALER_L1, 10_000_000.0),
            ],
            genesis_hash: "BLACKBOOK_DEVNET_GENESIS_V1",
            protocol_version: ProtocolVersion::new(3, 0, 0),
        },
    }
}
```

---

## Implementation Plan

### Phase 1: Network Isolation (Week 1)
- [ ] Create `NetworkConfig` and `Config` structs
- [ ] Add chain_id validation to all endpoints
- [ ] Separate database paths by network
- [ ] Update domain separation for new chain IDs
- [ ] Add `/network/info` endpoint

### Phase 2: Hot Upgrades Framework (Week 2)
- [ ] Create `ProtocolVersion` type
- [ ] Implement `ProtocolHandler` trait
- [ ] Build `VersionManager`
- [ ] Add upgrade scheduling endpoints
- [ ] Add rollback capability
- [ ] Add upgrade history tracking

### Phase 3: Testnet Specific Features (Week 3)
- [ ] Implement faucet endpoint (`POST /faucet/request`)
- [ ] Add rate limiting for faucet (per IP, per wallet)
- [ ] Create testnet genesis with 100M tBB
- [ ] Deploy testnet Supabase project
- [ ] Testnet block explorer

### Phase 4: Mainnet Hardening (Week 4)
- [ ] Disable faucet on mainnet
- [ ] Enforce USDC backing for all mints
- [ ] Production rate limiting
- [ ] Mainnet genesis (empty, USDC-backed only)
- [ ] Deploy mainnet Supabase project

### Phase 5: SDK Updates (Week 5)
- [ ] Add network selection to SDK
- [ ] Update Apollo wallet for network awareness
- [ ] Add network switching UI
- [ ] Testnet/Mainnet badge in wallet
- [ ] Cross-network transfer prevention

---

## Migration Strategy

### From Current State to Multi-Network

```
CURRENT STATE (Single Network)
│
│  ./blockchain_data/blockchain.redb
│  Chain ID: 0x01 (hardcoded)
│
▼

STEP 1: Add Network Awareness
│
│  Keep existing data as "mainnet"
│  Add NETWORK env var (default: devnet for backwards compat)
│
▼

STEP 2: Database Migration
│
│  mv ./blockchain_data ./blockchain_data/mainnet
│  Create empty ./blockchain_data/testnet
│  Create empty ./blockchain_data/devnet
│
▼

STEP 3: Hot Upgrades Integration
│
│  Start with version 3.0.0
│  Register all existing handlers
│  Enable upgrade scheduling
│
▼

STEP 4: Launch Testnet
│
│  Deploy testnet binary
│  Create testnet genesis
│  Enable faucet
│  Public testing begins
│
▼

STEP 5: Mainnet Launch
│
│  Deploy mainnet binary
│  Empty genesis (USDC-backed only)
│  Disable faucet
│  Production traffic

FINAL STATE (Multi-Network)
│
├── blockchain_data/mainnet/    (Chain ID: 0x01)
├── blockchain_data/testnet/    (Chain ID: 0x10)
└── blockchain_data/devnet/     (Chain ID: 0xFF)
```

---

## Supabase Multi-Environment

### Separate Projects

| Environment | Supabase Project | Purpose |
|-------------|------------------|---------|
| Mainnet | `blackbook-mainnet` | Production wallets |
| Testnet | `blackbook-testnet` | Test wallets |
| Devnet | `blackbook-devnet` | Development |

### Schema Consistency

All three projects use the **same schema** ([supabase-schema.sql](./supabase-schema.sql)):
- `public.profiles` - Usernames
- `public.user_vault` - Encrypted wallet data

### Cross-Environment Rules

1. **Wallets are network-specific**: Apollo on mainnet ≠ Apollo on testnet
2. **Same email can register on all networks**: `apollo@example.com` exists separately
3. **No cross-network data sharing**: Complete isolation
4. **Same recovery process**: SSS works identically on all networks

---

## SDK Network Selection

### JavaScript SDK Update

```javascript
// sdk/blackbook-wallet-sdk-v3.js

const NETWORKS = {
    mainnet: {
        chainId: 0x01,
        name: 'BlackBook Mainnet',
        rpcUrl: 'https://mainnet.blackbook.io',
        supabaseUrl: 'https://mainnet.supabase.co',
        explorerUrl: 'https://explorer.blackbook.io',
        symbol: 'BB',
        faucetEnabled: false
    },
    testnet: {
        chainId: 0x10,
        name: 'BlackBook Testnet',
        rpcUrl: 'https://testnet.blackbook.io',
        supabaseUrl: 'https://testnet.supabase.co',
        explorerUrl: 'https://testnet-explorer.blackbook.io',
        symbol: 'tBB',
        faucetEnabled: true
    },
    devnet: {
        chainId: 0xFF,
        name: 'BlackBook Devnet',
        rpcUrl: 'http://localhost:8082',
        supabaseUrl: 'http://localhost:54321',
        explorerUrl: 'http://localhost:3000',
        symbol: 'dBB',
        faucetEnabled: true
    }
};

class BlackBookSDK {
    constructor(network = 'devnet') {
        this.network = NETWORKS[network] || NETWORKS.devnet;
        this.chainId = this.network.chainId;
    }
    
    switchNetwork(network) {
        if (!NETWORKS[network]) {
            throw new Error(`Unknown network: ${network}`);
        }
        this.network = NETWORKS[network];
        this.chainId = this.network.chainId;
    }
    
    async signTransaction(session, from, to, amount) {
        // Uses this.chainId for domain separation
        const domainPrefix = `BLACKBOOK_L${this.chainId}/transfer`;
        // ... rest of signing logic
    }
}
```

---

## Monitoring & Alerts

### Prometheus Metrics per Network

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'blackbook-mainnet'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    params:
      network: ['mainnet']
      
  - job_name: 'blackbook-testnet'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/metrics'
    params:
      network: ['testnet']
```

### Grafana Dashboard Labels

```
Network: mainnet | testnet | devnet
Chain ID: 0x01 | 0x10 | 0xFF
Protocol Version: 3.0.0 → 3.1.0 → 3.2.0
```

---

## Summary

### Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Chain IDs | 0x01, 0x10, 0xFF | Clear separation, no collision |
| Hot Upgrades | Slot-based activation | Predictable timing |
| Database | Separate ReDB per network | Complete isolation |
| Supabase | Separate projects | Privacy, compliance |
| Faucet | Testnet/Devnet only | Prevent mainnet abuse |
| Genesis | Empty mainnet | All BB must be USDC-backed |

### Implementation Priority

1. **HIGH**: Chain ID expansion and domain separation (prevents replay attacks)
2. **HIGH**: Database separation (data integrity)
3. **MEDIUM**: Hot upgrades framework (operational flexibility)
4. **MEDIUM**: Faucet for testnet (developer experience)
5. **LOW**: Multi-network SDK (can use separate configs initially)

---

**Next Steps:**
1. Review and approve this plan
2. Create implementation tickets
3. Start Phase 1 (Network Isolation)
4. Deploy testnet by February 7, 2026
5. Mainnet hardening by February 14, 2026

---

*Document maintained by: BlackBook Core Team*  
*Last Updated: January 27, 2026*
