//! Community watchlists: opt-in, non-binding lists of suspected colluding
//! node clusters. Maintained by community contributors, signed with known
//! identities. Advisory only — does not interact with the slashing oracle.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// How often to re-fetch remote watchlists.
const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // 6 hours

// ── Data model ───────────────────────────────────────────────────────

/// A signed community watchlist fetched from a remote URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watchlist {
    /// Human-readable name (e.g. "ShieldNode Core Team").
    pub name: String,
    /// Who maintains this list.
    pub maintainer: String,
    /// Unix timestamp when the list was last updated by the maintainer.
    pub updated_at: u64,
    /// Flagged node entries.
    pub entries: Vec<WatchlistEntry>,
    /// Hex-encoded Ed25519 signature over the canonical JSON of the
    /// above fields (name + maintainer + updated_at + entries).
    /// Verification is optional — unsigned lists are allowed but shown
    /// as "unverified" in the UI.
    #[serde(default)]
    pub signature: Option<String>,
}

/// A single flagged node in a watchlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistEntry {
    /// Node ID (hex-encoded public key).
    pub node_id: String,
    /// Human-readable reason for flagging.
    pub reason: String,
    /// Category of suspicion.
    #[serde(default = "default_category")]
    pub category: String,
}

fn default_category() -> String {
    "collusion".to_string()
}

// ── Subscription config ──────────────────────────────────────────────

/// User's subscription to a remote watchlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistSubscription {
    /// URL to fetch the watchlist JSON from.
    pub url: String,
    /// Whether this subscription is currently active.
    pub enabled: bool,
    /// Optional display name override.
    #[serde(default)]
    pub label: String,
}

// ── Manager ──────────────────────────────────────────────────────────

/// Manages fetched watchlists and their cached state.
#[derive(Debug, Default)]
pub struct WatchlistManager {
    /// Loaded watchlists keyed by subscription URL.
    lists: Vec<(String, Watchlist)>,
    /// When the lists were last refreshed.
    last_refresh: Option<std::time::Instant>,
}

impl WatchlistManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all flagged node IDs across all loaded watchlists.
    pub fn flagged_node_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for (_, wl) in &self.lists {
            for entry in &wl.entries {
                ids.insert(entry.node_id.clone());
            }
        }
        ids
    }

    /// Check if a specific node is flagged by any watchlist.
    pub fn is_flagged(&self, node_id: &str) -> bool {
        self.lists
            .iter()
            .any(|(_, wl)| wl.entries.iter().any(|e| e.node_id == node_id))
    }

    /// Get the reasons a node is flagged (across all lists).
    pub fn reasons_for(&self, node_id: &str) -> Vec<String> {
        let mut reasons = Vec::new();
        for (_, wl) in &self.lists {
            for entry in &wl.entries {
                if entry.node_id == node_id {
                    reasons.push(format!("{}: {}", wl.name, entry.reason));
                }
            }
        }
        reasons
    }

    /// Whether enough time has passed to warrant a refresh.
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh
            .map(|t| t.elapsed() >= REFRESH_INTERVAL)
            .unwrap_or(true)
    }

    /// Store fetched watchlist results. Call after `fetch_all_watchlists`.
    pub fn apply_fetched(&mut self, lists: Vec<(String, Watchlist)>) {
        self.lists = lists;
        self.last_refresh = Some(std::time::Instant::now());
    }

    /// Summary for the frontend: list name, entry count, last update.
    pub fn summaries(&self) -> Vec<WatchlistSummary> {
        self.lists
            .iter()
            .map(|(url, wl)| WatchlistSummary {
                url: url.clone(),
                name: wl.name.clone(),
                maintainer: wl.maintainer.clone(),
                entry_count: wl.entries.len(),
                updated_at: wl.updated_at,
                signed: wl.signature.is_some(),
            })
            .collect()
    }
}

/// Frontend-safe summary of a loaded watchlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchlistSummary {
    pub url: String,
    pub name: String,
    pub maintainer: String,
    pub entry_count: usize,
    pub updated_at: u64,
    pub signed: bool,
}

/// Full watchlist state returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchlistInfo {
    pub subscriptions: Vec<WatchlistSubscription>,
    pub loaded: Vec<WatchlistSummary>,
}

// ── Fetch ────────────────────────────────────────────────────────────

/// Fetch all enabled subscriptions concurrently. Returns results to be
/// passed to `WatchlistManager::apply_fetched`. Does not hold any lock.
pub async fn fetch_all_watchlists(
    subscriptions: &[WatchlistSubscription],
) -> Vec<(String, Watchlist)> {
    use futures::future::join_all;

    let futures: Vec<_> = subscriptions
        .iter()
        .filter(|s| s.enabled)
        .map(|sub| async {
            match fetch_watchlist(&sub.url).await {
                Ok(wl) => {
                    info!(
                        url = %sub.url,
                        name = %wl.name,
                        entries = wl.entries.len(),
                        "loaded watchlist"
                    );
                    Some((sub.url.clone(), wl))
                }
                Err(e) => {
                    warn!(url = %sub.url, error = %e, "failed to fetch watchlist");
                    None
                }
            }
        })
        .collect();

    join_all(futures).await.into_iter().flatten().collect()
}

async fn fetch_watchlist(url: &str) -> Result<Watchlist, String> {
    // For file:// URLs or local paths, read from disk.
    if let Some(path) = url.strip_prefix("file://") {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read local watchlist: {e}"))?;
        let wl: Watchlist =
            serde_json::from_str(&data).map_err(|e| format!("invalid watchlist JSON: {e}"))?;
        return Ok(wl);
    }

    // Remote HTTP(S) fetch.
    let resp = reqwest::get(url)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?;

    let wl: Watchlist =
        serde_json::from_str(&body).map_err(|e| format!("invalid watchlist JSON: {e}"))?;

    // Basic staleness check: reject lists older than 90 days.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(wl.updated_at) > 90 * 24 * 60 * 60 {
        return Err("watchlist is older than 90 days — possibly stale".to_string());
    }

    Ok(wl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_watchlist() -> Watchlist {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Watchlist {
            name: "Test Watchlist".to_string(),
            maintainer: "tester".to_string(),
            updated_at: now,
            entries: vec![
                WatchlistEntry {
                    node_id: "node-a".to_string(),
                    reason: "suspected collusion cluster".to_string(),
                    category: "collusion".to_string(),
                },
                WatchlistEntry {
                    node_id: "node-b".to_string(),
                    reason: "correlated uptime pattern".to_string(),
                    category: "collusion".to_string(),
                },
            ],
            signature: None,
        }
    }

    #[test]
    fn flagged_nodes_collected() {
        let mut mgr = WatchlistManager::new();
        mgr.lists
            .push(("test-url".to_string(), sample_watchlist()));
        let flagged = mgr.flagged_node_ids();
        assert!(flagged.contains("node-a"));
        assert!(flagged.contains("node-b"));
        assert!(!flagged.contains("node-c"));
    }

    #[test]
    fn is_flagged_check() {
        let mut mgr = WatchlistManager::new();
        mgr.lists
            .push(("test-url".to_string(), sample_watchlist()));
        assert!(mgr.is_flagged("node-a"));
        assert!(!mgr.is_flagged("node-c"));
    }

    #[test]
    fn reasons_aggregated() {
        let mut mgr = WatchlistManager::new();
        mgr.lists
            .push(("url-1".to_string(), sample_watchlist()));

        let mut wl2 = sample_watchlist();
        wl2.name = "Second List".to_string();
        wl2.entries = vec![WatchlistEntry {
            node_id: "node-a".to_string(),
            reason: "funding pattern".to_string(),
            category: "sybil".to_string(),
        }];
        mgr.lists.push(("url-2".to_string(), wl2));

        let reasons = mgr.reasons_for("node-a");
        assert_eq!(reasons.len(), 2);
        assert!(reasons[0].contains("Test Watchlist"));
        assert!(reasons[1].contains("Second List"));
    }

    #[test]
    fn empty_manager_flags_nothing() {
        let mgr = WatchlistManager::new();
        assert!(mgr.flagged_node_ids().is_empty());
        assert!(!mgr.is_flagged("node-a"));
        assert!(mgr.needs_refresh());
    }

    #[test]
    fn summaries_reflect_loaded_lists() {
        let mut mgr = WatchlistManager::new();
        mgr.lists
            .push(("https://example.com/wl.json".to_string(), sample_watchlist()));
        let sums = mgr.summaries();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].name, "Test Watchlist");
        assert_eq!(sums[0].entry_count, 2);
        assert!(!sums[0].signed);
    }

    #[tokio::test]
    async fn fetch_local_file() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wl = Watchlist {
            name: "Local Test".to_string(),
            maintainer: "test".to_string(),
            updated_at: now,
            entries: vec![WatchlistEntry {
                node_id: "node-x".to_string(),
                reason: "test".to_string(),
                category: "collusion".to_string(),
            }],
            signature: None,
        };
        let dir = std::env::temp_dir().join("shieldnode-test-watchlist.json");
        std::fs::write(&dir, serde_json::to_string(&wl).unwrap()).unwrap();

        let url = format!("file://{}", dir.display());
        let loaded = fetch_watchlist(&url).await.unwrap();
        assert_eq!(loaded.name, "Local Test");
        assert_eq!(loaded.entries.len(), 1);

        std::fs::remove_file(&dir).ok();
    }
}
