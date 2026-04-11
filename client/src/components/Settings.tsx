import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useWallet } from "../hooks/useWallet";

interface WatchlistSubscription {
  url: string;
  enabled: boolean;
  label: string;
}

interface WatchlistSummary {
  url: string;
  name: string;
  maintainer: string;
  entryCount: number;
  updatedAt: number;
  signed: boolean;
}

interface WatchlistInfo {
  subscriptions: WatchlistSubscription[];
  loaded: WatchlistSummary[];
}

interface SettingsPayload {
  rpc_url: string;
  chain_id: number;
  auto_rotate: boolean;
  circuit_rotation_interval_secs: number;
  kill_switch: boolean;
  gas_price_ceiling_gwei: number;
  strict_network_size: boolean;
  cover_traffic: string;
  settlement_mode: string;
  preferred_nodes: string[];
  watchlist_subscriptions: WatchlistSubscription[];
}

// Local UI state with user-friendly field names.
interface SettingsState {
  rpcEndpoint: string;
  autoRotate: boolean;
  rotationIntervalMin: number;
  killSwitch: boolean;
  gasCeiling: number;
  strictNetwork: boolean;
  coverTraffic: string;
  settlementMode: string;
  pinnedEntry: string;
  pinnedRelay: string;
  pinnedExit: string;
  // Fields not editable in the UI but preserved on round-trip.
  _chainId: number;
  _watchlistSubscriptions: WatchlistSubscription[];
}

function toLocal(p: SettingsPayload): SettingsState {
  return {
    rpcEndpoint: p.rpc_url,
    autoRotate: p.auto_rotate,
    rotationIntervalMin: Math.round(p.circuit_rotation_interval_secs / 60),
    killSwitch: p.kill_switch,
    gasCeiling: p.gas_price_ceiling_gwei,
    strictNetwork: p.strict_network_size,
    coverTraffic: p.cover_traffic,
    settlementMode: p.settlement_mode,
    pinnedEntry: p.preferred_nodes[0] || "",
    pinnedRelay: p.preferred_nodes[1] || "",
    pinnedExit: p.preferred_nodes[2] || "",
    _chainId: p.chain_id,
    _watchlistSubscriptions: p.watchlist_subscriptions || [],
  };
}

function toPayload(s: SettingsState): SettingsPayload {
  return {
    rpc_url: s.rpcEndpoint,
    chain_id: s._chainId,
    auto_rotate: s.autoRotate,
    circuit_rotation_interval_secs: s.rotationIntervalMin * 60,
    kill_switch: s.killSwitch,
    gas_price_ceiling_gwei: s.gasCeiling,
    strict_network_size: s.strictNetwork,
    cover_traffic: s.coverTraffic,
    settlement_mode: s.settlementMode,
    preferred_nodes: [s.pinnedEntry, s.pinnedRelay, s.pinnedExit],
    watchlist_subscriptions: s._watchlistSubscriptions,
  };
}

function Toggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm" style={{ color: "var(--text-primary)" }}>{label}</p>
        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>{description}</p>
      </div>
      <button
        onClick={() => onChange(!checked)}
        className="w-11 h-6 rounded-full relative transition-colors duration-200 cursor-pointer"
        style={{ background: checked ? "var(--accent-green)" : "var(--border-color)" }}
      >
        <span
          className="absolute top-0.5 w-5 h-5 rounded-full transition-transform duration-200"
          style={{
            background: "white",
            left: "2px",
            transform: checked ? "translateX(20px)" : "translateX(0)",
          }}
        />
      </button>
    </div>
  );
}

export function Settings() {
  const { wallet, connectWallet, disconnectWallet } = useWallet();
  const [walletError, setWalletError] = useState<string | null>(null);

  const [settings, setSettings] = useState<SettingsState>({
    rpcEndpoint: "",
    autoRotate: false,
    rotationIntervalMin: 10,
    killSwitch: true,
    gasCeiling: 10,
    strictNetwork: false,
    coverTraffic: "low",
    settlementMode: "auto",
    pinnedEntry: "",
    pinnedRelay: "",
    pinnedExit: "",
    _chainId: 11155111,
    _watchlistSubscriptions: [],
  });
  const [loaded, setLoaded] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Load settings from backend on mount; clean up debounce on unmount.
  useEffect(() => {
    invoke<SettingsPayload>("get_settings")
      .then((payload) => {
        setSettings(toLocal(payload));
        setLoaded(true);
      })
      .catch(() => setLoaded(true)); // show defaults on error
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  // Debounced save to backend.
  const save = useCallback((updated: SettingsState) => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      invoke("update_settings", { settings: toPayload(updated) }).catch(() => {});
    }, 500);
  }, []);

  const update = <K extends keyof SettingsState>(key: K, value: SettingsState[K]) => {
    setSettings((prev) => {
      const next = { ...prev, [key]: value };
      save(next);
      return next;
    });
  };

  if (!loaded) {
    return (
      <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Loading settings...
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* ── Wallet ───────────────────────────────────── */}
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
          Wallet
        </label>
        {wallet.connected ? (
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-mono truncate" style={{ color: "var(--accent-green)" }}>
              {wallet.address?.slice(0, 6)}...{wallet.address?.slice(-4)}
            </span>
            <button
              onClick={() => { disconnectWallet(); setWalletError(null); }}
              className="text-xs px-2 py-1 rounded cursor-pointer"
              style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-secondary)" }}
            >
              Disconnect
            </button>
          </div>
        ) : (
          <button
            onClick={async () => {
              setWalletError(null);
              try { await connectWallet(); }
              catch (e: any) { setWalletError(e?.message || "connection failed"); }
            }}
            className="w-full px-3 py-2 rounded text-sm cursor-pointer"
            style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
          >
            Connect Wallet
          </button>
        )}
        {walletError && (
          <p className="text-xs mt-1" style={{ color: "var(--accent-red, #ef4444)" }}>{walletError}</p>
        )}
        <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
          {wallet.mode === "walletconnect"
            ? "Signing via connected wallet (MetaMask, etc.)"
            : "Signing with local key from OS keychain"}
        </p>
      </div>

      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
          RPC Endpoint
        </label>
        <input
          type="text"
          value={settings.rpcEndpoint}
          onChange={(e) => update("rpcEndpoint", e.target.value)}
          className="w-full px-3 py-2 rounded text-sm font-mono"
          style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
        />
      </div>

      <Toggle
        label="Auto-rotate circuits"
        description="Periodically rebuild circuit through different nodes"
        checked={settings.autoRotate}
        onChange={(v) => update("autoRotate", v)}
      />

      {settings.autoRotate && (
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
            Rotation interval (minutes)
          </label>
          <input
            type="number"
            min={1}
            max={60}
            step={1}
            value={settings.rotationIntervalMin}
            onChange={(e) => update("rotationIntervalMin", Number(e.target.value))}
            className="w-full px-3 py-2 rounded text-sm font-mono"
            style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
          />
        </div>
      )}

      <Toggle
        label="Kill switch"
        description="Block traffic if VPN disconnects"
        checked={settings.killSwitch}
        onChange={(v) => update("killSwitch", v)}
      />

      <Toggle
        label="Strict network size"
        description="Refuse to connect if fewer than 20 active nodes"
        checked={settings.strictNetwork}
        onChange={(v) => update("strictNetwork", v)}
      />

      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
          Cover traffic
        </label>
        <select
          value={settings.coverTraffic}
          onChange={(e) => update("coverTraffic", e.target.value)}
          className="w-full px-3 py-2 rounded text-sm"
          style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
        >
          <option value="off">Off (no overhead)</option>
          <option value="low">Low — 10 pps (~1.1 GB/day)</option>
          <option value="high">High — 50 pps (~5.5 GB/day)</option>
        </select>
        <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
          Prevents timing-based activity detection
        </p>
      </div>

      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
          Settlement mode
        </label>
        <select
          value={settings.settlementMode}
          onChange={(e) => update("settlementMode", e.target.value)}
          className="w-full px-3 py-2 rounded text-sm"
          style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
        >
          <option value="auto">Auto (ZK if available, plaintext fallback)</option>
          <option value="zk">ZK only (privacy-preserving)</option>
          <option value="plaintext">Plaintext only (legacy)</option>
        </select>
        <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
          ZK hides session metadata on-chain
        </p>
      </div>

      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
          Gas price ceiling (Gwei)
        </label>
        <input
          type="number"
          min={0}
          step={1}
          value={settings.gasCeiling}
          onChange={(e) => update("gasCeiling", Number(e.target.value))}
          className="w-full px-3 py-2 rounded text-sm font-mono"
          style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
        />
      </div>

      <div>
        <label className="block text-xs font-medium mb-2" style={{ color: "var(--text-secondary)" }}>
          Circuit pinning (leave blank for random)
        </label>
        {(["pinnedEntry", "pinnedRelay", "pinnedExit"] as const).map((key, i) => (
          <div key={key} className="mb-2">
            <label className="block text-xs mb-0.5" style={{ color: "var(--text-secondary)" }}>
              {["Entry node", "Relay node", "Exit node"][i]}
            </label>
            <input
              type="text"
              placeholder="node-id (optional)"
              value={settings[key]}
              onChange={(e) => update(key, e.target.value)}
              className="w-full px-3 py-1.5 rounded text-xs font-mono"
              style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
            />
          </div>
        ))}
      </div>

      <WatchlistSection />

      <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Settings take effect on next connection.
      </p>
    </div>
  );
}

// ── Watchlist management section ─────────────────────────────────────

function WatchlistSection() {
  const [info, setInfo] = useState<WatchlistInfo | null>(null);
  const [newUrl, setNewUrl] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(() => {
    invoke<WatchlistInfo>("get_watchlists").then(setInfo).catch(() => {});
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const addWatchlist = async () => {
    const url = newUrl.trim();
    if (!url) return;
    setError("");
    try {
      await invoke("add_watchlist", { url });
      setNewUrl("");
      refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const removeWatchlist = async (url: string) => {
    try {
      await invoke("remove_watchlist", { url });
    } catch (e) {
      setError(String(e));
    }
    refresh();
  };

  return (
    <div>
      <label className="block text-xs font-medium mb-2" style={{ color: "var(--text-secondary)" }}>
        Community watchlists
      </label>
      <p className="text-xs mb-2" style={{ color: "var(--text-secondary)" }}>
        Opt-in lists of suspected colluding nodes. Advisory only.
      </p>

      {info && info.loaded.length > 0 && (
        <div className="flex flex-col gap-1.5 mb-2">
          {info.loaded.map((wl) => (
            <div
              key={wl.url}
              className="flex items-center justify-between px-2 py-1.5 rounded text-xs"
              style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)" }}
            >
              <div className="flex-1 min-w-0">
                <span style={{ color: "var(--text-primary)" }}>{wl.name}</span>
                <span className="ml-2" style={{ color: "var(--text-secondary)" }}>
                  {wl.entryCount} node{wl.entryCount !== 1 ? "s" : ""}
                  {wl.signed ? " · signed" : " · unverified"}
                </span>
              </div>
              <button
                onClick={() => removeWatchlist(wl.url)}
                className="ml-2 px-1.5 text-xs rounded cursor-pointer"
                style={{ color: "var(--accent-red, #ef4444)" }}
              >
                remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        <input
          type="text"
          placeholder="https://example.com/watchlist.json"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addWatchlist()}
          className="flex-1 px-3 py-1.5 rounded text-xs font-mono"
          style={{ background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}
        />
        <button
          onClick={addWatchlist}
          className="px-3 py-1.5 rounded text-xs cursor-pointer"
          style={{ background: "var(--accent-green)", color: "white" }}
        >
          Add
        </button>
      </div>
      {error && (
        <p className="text-xs mt-1" style={{ color: "var(--accent-red, #ef4444)" }}>{error}</p>
      )}
    </div>
  );
}
