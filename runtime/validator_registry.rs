//! Permissioned Validator Registry — Phase 7A + Phase 1 (Rotating Leaders)
//!
//! Maintains the static whitelist of approved validator / reader nodes that
//! are allowed to send or receive Turbine tick shreds, AND tracks stake
//! weights for deterministic leader-schedule generation.
//!
//! Config sources (in priority order):
//! 1. `APPROVED_VALIDATORS` env var (if set, REPLACES TOML entirely).
//!    Format: `"label:pubkey_hex@ip:port:stake;..."`  (stake in lamports, optional)
//!    (label, stake, and http_port are optional — bare `pubkey_hex@ip:port` is accepted)
//! 2. TOML file at the path given by `VALIDATOR_CONFIG_PATH` env var,
//!    or `config.toml` in the working directory by default.
//!
//! TOML format:
//! ```toml
//! [[validators]]
//! label  = "genesis-writer"
//! pubkey = "abcd1234..."   # 64 hex chars = 32-byte Ed25519 pubkey
//! addr   = "91.98.196.34:8004"
//! stake_lamports = 1_000_000_000   # optional, default 1B = 10,000 BB
//! http_port = 8080                 # optional, default 8080
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ── TOML schema ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TomlConfig {
    #[serde(default)]
    validators: Vec<TomlValidator>,
}

#[derive(Debug, Deserialize)]
struct TomlValidator {
    #[serde(default)]
    label: String,
    pubkey: String,
    addr: String,
    #[serde(default = "default_stake")]
    stake_lamports: u64,
    #[serde(default = "default_http_port")]
    http_port: u16,
}

fn default_stake() -> u64 { 1_000_000_000 } // 10,000 BB
fn default_http_port() -> u16 { 8080 }

// ── Public types ──────────────────────────────────────────────────────────────

/// A single approved validator / reader node.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovedValidator {
    /// Ed25519 pubkey bytes (32 bytes).
    pub pubkey: [u8; 32],
    /// Hex representation of the pubkey (lowercase, 64 chars).
    pub pubkey_hex: String,
    /// UDP address for Turbine shred delivery.
    pub udp_addr: SocketAddr,
    /// Source IP extracted from `udp_addr` for fast packet-layer gating.
    pub ip: IpAddr,
    /// Human-readable label (from config or auto-generated).
    pub label: String,
    /// Stake weight in lamports for leader schedule + Tower BFT voting.
    /// Default: 1_000_000_000 (10,000 BB).
    pub stake_lamports: u64,
    /// HTTP port for RPC forwarding. Default: 8080.
    pub http_port: u16,
}

/// Immutable whitelist of approved validators.
///
/// Built once at startup via [`ValidatorRegistry::load`] and shared as
/// `Arc<ValidatorRegistry>` across Turbine components.
pub struct ValidatorRegistry {
    validators: Vec<ApprovedValidator>,
    /// Fast lookup: source IP → index in `validators`.
    by_ip: HashMap<IpAddr, usize>,
    /// Fast lookup: pubkey bytes → index in `validators`.
    by_pubkey: HashMap<[u8; 32], usize>,
}

impl ValidatorRegistry {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Return a registry with zero entries (local single-node dev mode).
    ///
    /// Used as the fallback when `load()` returns `Err` (e.g. bad config.toml
    /// placeholder IPs) so startup never panics just because Turbine peers are
    /// not yet configured.
    pub fn empty() -> Self {
        Self { validators: Vec::new(), by_ip: HashMap::new(), by_pubkey: HashMap::new() }
    }

    /// Load the registry.
    ///
    /// - `toml_path`: path to the TOML config file (if `None`, uses
    ///   `VALIDATOR_CONFIG_PATH` env var, then falls back to `"config.toml"`).
    /// - `env_override`: contents of the `APPROVED_VALIDATORS` env var (if
    ///   `Some` and non-empty, **replaces** the TOML source entirely).
    ///
    /// Returns `Err` only for parse errors that would silently misconfigure the
    /// node. An empty registry is allowed (returns `Ok` with a warning).
    pub fn load(toml_path: Option<&str>, env_override: Option<&str>) -> Result<Self, String> {
        let raw_entries: Vec<RawEntry>;

        if let Some(env_val) = env_override {
            if !env_val.is_empty() {
                // Env overrides TOML entirely.
                raw_entries = parse_env_var(env_val)?;
                info!(
                    "🔐 ValidatorRegistry: loaded {} entries from APPROVED_VALIDATORS env",
                    raw_entries.len()
                );
            } else {
                raw_entries = load_toml(toml_path)?;
            }
        } else {
            raw_entries = load_toml(toml_path)?;
        }

        build_registry(raw_entries)
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Returns `true` if the given source IP is from an approved validator.
    /// Called at the UDP socket layer before any deserialization (Phase 7B).
    #[inline]
    pub fn is_approved_ip(&self, ip: &IpAddr) -> bool {
        self.by_ip.contains_key(ip)
    }

    /// Look up an approved validator by its Ed25519 pubkey bytes.
    /// Returns `None` if the pubkey is not in the whitelist.
    pub fn get_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<&ApprovedValidator> {
        self.by_pubkey.get(pubkey).map(|&i| &self.validators[i])
    }

    /// Iterator over all UDP addresses to broadcast shreds to (Writer side).
    pub fn udp_targets(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.validators.iter().map(|v| v.udp_addr)
    }

    /// Number of approved validators in the registry.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// `true` if no validators are registered.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// All registered validators (for diagnostics / status endpoint).
    pub fn all(&self) -> &[ApprovedValidator] {
        &self.validators
    }

    /// Look up by label.
    pub fn get_by_label(&self, label: &str) -> Option<&ApprovedValidator> {
        self.validators.iter().find(|v| v.label == label)
    }

    /// Total stake across all validators.
    pub fn total_stake(&self) -> u64 {
        self.validators.iter().map(|v| v.stake_lamports).sum()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Intermediate parsed entry before building the final ApprovedValidator.
struct RawEntry {
    label: String,
    pubkey_hex: String,
    addr: String,
    stake_lamports: u64,
    http_port: u16,
}

fn load_toml(path_override: Option<&str>) -> Result<Vec<RawEntry>, String> {
    let path = path_override
        .map(str::to_string)
        .unwrap_or_else(|| {
            std::env::var("VALIDATOR_CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string())
        });

    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                "⚠️  ValidatorRegistry: config file '{}' not found — registry is empty. \
                 Set APPROVED_VALIDATORS or create config.toml to enable Turbine shred delivery.",
                path
            );
            return Ok(vec![]);
        }
        Err(e) => return Err(format!("Failed to read '{}': {}", path, e)),
    };

    let cfg: TomlConfig =
        toml::from_str(&contents).map_err(|e| format!("TOML parse error in '{}': {}", path, e))?;

    let entries: Vec<RawEntry> = cfg
        .validators
        .into_iter()
        .map(|v| RawEntry {
            label: v.label,
            pubkey_hex: v.pubkey,
            addr: v.addr,
            stake_lamports: v.stake_lamports,
            http_port: v.http_port,
        })
        .collect();

    info!("🔐 ValidatorRegistry: loaded entries from '{}'", path);
    Ok(entries)
}

/// Parse `APPROVED_VALIDATORS` env value.
/// Accepts: `"label:hex@ip:port:stake;hex@ip:port"` (semicolon-separated; label + stake optional).
fn parse_env_var(raw: &str) -> Result<Vec<RawEntry>, String> {
    raw.split(';')
        .filter(|s| !s.trim().is_empty())
        .enumerate()
        .map(|(i, entry)| {
            let entry = entry.trim();
            let at_pos = entry
                .rfind('@')
                .ok_or_else(|| format!("APPROVED_VALIDATORS entry #{}: missing '@' separator in '{}'", i, entry))?;

            let left = &entry[..at_pos];
            let addr_part = entry[at_pos + 1..].to_string();

            // addr_part may be "ip:port" or "ip:port:stake" or "ip:port:stake:http_port"
            let addr_parts: Vec<&str> = addr_part.splitn(4, ':').collect();
            let addr = if addr_parts.len() >= 2 {
                format!("{}:{}", addr_parts[0], addr_parts[1])
            } else {
                return Err(format!("APPROVED_VALIDATORS entry #{}: bad addr '{}'", i, addr_part));
            };
            let stake: u64 = addr_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(1_000_000_000);
            let http_port: u16 = addr_parts.get(3).and_then(|p| p.parse().ok()).unwrap_or(8080);

            // Left part: optional "label:" prefix.
            let (label, pubkey_hex) = if let Some(colon) = left.find(':') {
                (left[..colon].to_string(), left[colon + 1..].to_string())
            } else {
                (format!("validator-{}", i), left.to_string())
            };

            Ok(RawEntry { label, pubkey_hex, addr, stake_lamports: stake, http_port })
        })
        .collect()
}

fn build_registry(
    raw: Vec<RawEntry>,
) -> Result<ValidatorRegistry, String> {
    let mut validators: Vec<ApprovedValidator> = Vec::new();
    let mut by_ip: HashMap<IpAddr, usize> = HashMap::new();
    let mut by_pubkey: HashMap<[u8; 32], usize> = HashMap::new();
    let mut seen_pubkeys: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for entry in raw {
        // Validate pubkey hex.
        let pubkey_hex = entry.pubkey_hex.trim().to_lowercase();
        if pubkey_hex.len() != 64 {
            return Err(format!(
                "ValidatorRegistry: pubkey '{}' for '{}' must be 64 hex chars (got {})",
                pubkey_hex, entry.label, pubkey_hex.len()
            ));
        }
        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|e| format!("ValidatorRegistry: bad pubkey hex '{}': {}", pubkey_hex, e))?;
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);

        // Dedup by pubkey.
        if !seen_pubkeys.insert(pubkey) {
            warn!(
                "⚠️  ValidatorRegistry: duplicate pubkey '{}' (label='{}') — skipping",
                pubkey_hex, entry.label
            );
            continue;
        }

        // Validate UDP address.
        let udp_addr: SocketAddr = entry.addr
            .parse()
            .map_err(|e| format!("ValidatorRegistry: bad addr '{}' for '{}': {}", entry.addr, entry.label, e))?;

        let ip = udp_addr.ip();
        let idx = validators.len();

        validators.push(ApprovedValidator {
            pubkey,
            pubkey_hex,
            udp_addr,
            ip,
            label: entry.label,
            stake_lamports: entry.stake_lamports,
            http_port: entry.http_port,
        });

        by_ip.insert(ip, idx);
        by_pubkey.insert(pubkey, idx);
    }

    if validators.is_empty() {
        warn!(
            "⚠️  ValidatorRegistry: no approved validators configured. \
             Turbine shred delivery is disabled. \
             Add [[validators]] entries to config.toml or set APPROVED_VALIDATORS."
        );
    } else {
        info!(
            "✅ ValidatorRegistry: {} approved validator(s):",
            validators.len()
        );
        for v in &validators {
            info!("   • {} — pubkey={} addr={}", v.label, &v.pubkey_hex[..16], v.udp_addr);
        }
    }

    Ok(ValidatorRegistry { validators, by_ip, by_pubkey })
}
