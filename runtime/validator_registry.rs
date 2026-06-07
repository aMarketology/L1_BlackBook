//! Permissioned Validator Registry — Phase 7A
//!
//! Maintains the static whitelist of approved validator / reader nodes that
//! are allowed to send or receive Turbine tick shreds.
//!
//! Config sources (in priority order):
//! 1. `APPROVED_VALIDATORS` env var (if set, REPLACES TOML entirely).
//!    Format: `"label:pubkey_hex@ip:port;pubkey_hex@ip:port;..."`
//!    (label is optional — bare `pubkey_hex@ip:port` is also accepted)
//! 2. TOML file at the path given by `VALIDATOR_CONFIG_PATH` env var,
//!    or `config.toml` in the working directory by default.
//!
//! TOML format:
//! ```toml
//! [[validators]]
//! label  = "genesis-writer"
//! pubkey = "abcd1234..."   # 64 hex chars = 32-byte Ed25519 pubkey
//! addr   = "91.98.196.34:8004"
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;
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
}

// ── Public types ──────────────────────────────────────────────────────────────

/// A single approved validator / reader node.
#[derive(Debug, Clone)]
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
        let raw_entries: Vec<(String, String, String)>; // (label, pubkey_hex, addr)

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
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn load_toml(path_override: Option<&str>) -> Result<Vec<(String, String, String)>, String> {
    let path = path_override
        .map(str::to_string)
        .unwrap_or_else(|| {
            std::env::var("VALIDATOR_CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string())
        });

    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Missing config file is non-fatal — node may run with empty registry (dev mode).
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

    let entries = cfg
        .validators
        .into_iter()
        .map(|v| (v.label, v.pubkey, v.addr))
        .collect();

    info!("🔐 ValidatorRegistry: loaded entries from '{}'", path);
    Ok(entries)
}

/// Parse `APPROVED_VALIDATORS` env value.
/// Accepts: `"label:hex@ip:port;hex@ip:port"` (semicolon-separated; label optional).
fn parse_env_var(raw: &str) -> Result<Vec<(String, String, String)>, String> {
    raw.split(';')
        .filter(|s| !s.trim().is_empty())
        .enumerate()
        .map(|(i, entry)| {
            let entry = entry.trim();
            // Split on '@' to separate (label:pubkey) from addr.
            let at_pos = entry
                .rfind('@')
                .ok_or_else(|| format!("APPROVED_VALIDATORS entry #{}: missing '@' separator in '{}'", i, entry))?;

            let left = &entry[..at_pos];
            let addr = entry[at_pos + 1..].to_string();

            // Left part: optional "label:" prefix.
            let (label, pubkey_hex) = if let Some(colon) = left.find(':') {
                (left[..colon].to_string(), left[colon + 1..].to_string())
            } else {
                (format!("validator-{}", i), left.to_string())
            };

            Ok((label, pubkey_hex, addr))
        })
        .collect()
}

fn build_registry(
    raw: Vec<(String, String, String)>,
) -> Result<ValidatorRegistry, String> {
    let mut validators: Vec<ApprovedValidator> = Vec::new();
    let mut by_ip: HashMap<IpAddr, usize> = HashMap::new();
    let mut by_pubkey: HashMap<[u8; 32], usize> = HashMap::new();
    let mut seen_pubkeys: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for (label, pubkey_hex, addr_str) in raw {
        // Validate pubkey hex.
        let pubkey_hex = pubkey_hex.trim().to_lowercase();
        if pubkey_hex.len() != 64 {
            return Err(format!(
                "ValidatorRegistry: pubkey '{}' for '{}' must be 64 hex chars (got {})",
                pubkey_hex, label, pubkey_hex.len()
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
                pubkey_hex, label
            );
            continue;
        }

        // Validate UDP address.
        let udp_addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("ValidatorRegistry: bad addr '{}' for '{}': {}", addr_str, label, e))?;

        let ip = udp_addr.ip();
        let idx = validators.len();

        validators.push(ApprovedValidator {
            pubkey,
            pubkey_hex,
            udp_addr,
            ip,
            label,
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
