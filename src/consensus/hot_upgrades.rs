//! Hot Upgrades - Live protocol upgrades without downtime
//! Propose → Vote (2/3 majority) → Activate at block height

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ============================================================================
// PROTOCOL VERSION
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ProtocolVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
    pub fn current() -> Self { Self::new(1, 0, 0) }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ============================================================================
// UPGRADE PROPOSAL
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UpgradeStatus {
    Proposed,
    Approved,
    Rejected,
    Activated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub id: String,
    pub name: String,
    pub target_version: ProtocolVersion,
    pub activation_block: u64,
    pub proposer: String,
    pub proposed_at: DateTime<Utc>,
    pub voting_deadline: DateTime<Utc>,
    pub status: UpgradeStatus,
    pub votes_for: HashSet<String>,
    pub votes_against: HashSet<String>,
    pub feature_flags: Vec<String>,
}

impl UpgradeProposal {
    pub fn new(name: String, target_version: ProtocolVersion, activation_block: u64, proposer: String) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            target_version,
            activation_block,
            proposer,
            proposed_at: now,
            voting_deadline: now + chrono::Duration::hours(72),
            status: UpgradeStatus::Proposed,
            votes_for: HashSet::new(),
            votes_against: HashSet::new(),
            feature_flags: Vec::new(),
        }
    }

    pub fn with_feature(mut self, flag: &str) -> Self {
        self.feature_flags.push(flag.into());
        self
    }

    pub fn voting_ended(&self) -> bool { Utc::now() > self.voting_deadline }
}

// ============================================================================
// FEATURE FLAGS
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureFlags {
    flags: HashMap<String, bool>,
}

impl FeatureFlags {
    pub fn new() -> Self { Self { flags: HashMap::new() } }
    pub fn is_enabled(&self, flag: &str) -> bool { *self.flags.get(flag).unwrap_or(&false) }
    pub fn enable(&mut self, flag: &str) { self.flags.insert(flag.into(), true); }
    pub fn disable(&mut self, flag: &str) { self.flags.insert(flag.into(), false); }
    pub fn enabled_list(&self) -> Vec<&str> {
        self.flags.iter().filter(|(_, &v)| v).map(|(k, _)| k.as_str()).collect()
    }
}

// ============================================================================
// UPGRADE MANAGER
// ============================================================================

pub struct UpgradeManager {
    pub version: ProtocolVersion,
    proposals: HashMap<String, UpgradeProposal>,
    history: Vec<UpgradeProposal>,
    pub features: FeatureFlags,
    voting_threshold: f64,
    current_block: u64,
}

impl Default for UpgradeManager {
    fn default() -> Self { Self::new() }
}

impl UpgradeManager {
    pub fn new() -> Self {
        let mut features = FeatureFlags::new();
        features.enable("base_transfers");
        features.enable("social_mining");
        features.enable("l2_bridge");

        Self {
            version: ProtocolVersion::current(),
            proposals: HashMap::new(),
            history: Vec::new(),
            features,
            voting_threshold: 0.67,
            current_block: 0,
        }
    }

    pub fn propose(&mut self, name: String, target: ProtocolVersion, activation_block: u64, proposer: String) -> Result<String, String> {
        if target <= self.version {
            return Err("target version must be greater than current".into());
        }
        if activation_block <= self.current_block {
            return Err("activation must be in future".into());
        }

        let proposal = UpgradeProposal::new(name, target, activation_block, proposer);
        let id = proposal.id.clone();
        self.proposals.insert(id.clone(), proposal);
        Ok(id)
    }

    pub fn vote(&mut self, proposal_id: &str, voter: String, approve: bool, total_validators: usize) -> Result<UpgradeStatus, String> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or("proposal not found")?;

        if proposal.voting_ended() { return Err("voting ended".into()); }
        if proposal.status != UpgradeStatus::Proposed { return Err("cannot vote".into()); }

        proposal.votes_for.remove(&voter);
        proposal.votes_against.remove(&voter);

        if approve {
            proposal.votes_for.insert(voter);
        } else {
            proposal.votes_against.insert(voter);
        }

        let votes_needed = (total_validators as f64 * self.voting_threshold).ceil() as usize;
        if proposal.votes_for.len() >= votes_needed {
            proposal.status = UpgradeStatus::Approved;
        }

        let reject_threshold = (total_validators as f64 * (1.0 - self.voting_threshold)).ceil() as usize;
        if proposal.votes_against.len() > reject_threshold {
            proposal.status = UpgradeStatus::Rejected;
        }

        Ok(proposal.status.clone())
    }

    pub fn process_block(&mut self, block: u64) -> Option<UpgradeProposal> {
        self.current_block = block;

        // Find proposal to activate
        let to_activate = self.proposals.iter()
            .find(|(_, p)| p.status == UpgradeStatus::Approved && p.activation_block == block)
            .map(|(id, _)| id.clone());

        if let Some(id) = to_activate {
            return self.activate(&id);
        }

        // Expire old proposals
        let expired: Vec<_> = self.proposals.iter()
            .filter(|(_, p)| p.status == UpgradeStatus::Proposed && p.voting_ended())
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(p) = self.proposals.get_mut(&id) {
                p.status = UpgradeStatus::Rejected;
            }
        }

        None
    }

    fn activate(&mut self, id: &str) -> Option<UpgradeProposal> {
        let proposal = self.proposals.get_mut(id)?;
        if proposal.status != UpgradeStatus::Approved { return None; }

        self.version = proposal.target_version.clone();

        for flag in &proposal.feature_flags {
            self.features.enable(flag);
        }

        proposal.status = UpgradeStatus::Activated;
        let proposal = self.proposals.remove(id)?;
        self.history.push(proposal.clone());
        Some(proposal)
    }

    pub fn get_proposal(&self, id: &str) -> Option<&UpgradeProposal> { self.proposals.get(id) }
    pub fn pending(&self) -> Vec<&UpgradeProposal> {
        self.proposals.values().filter(|p| matches!(p.status, UpgradeStatus::Proposed | UpgradeStatus::Approved)).collect()
    }
    pub fn history(&self) -> &[UpgradeProposal] { &self.history }
}
