import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SettingsPayload {
  rpc_url: string;
  chain_id: number;
  auto_rotate: boolean;
  circuit_rotation_interval_secs: number;
  kill_switch: boolean;
  gas_price_ceiling_gwei: number;
  strict_network_size: boolean;
  preferred_nodes: string[];
}

// Local UI state with user-friendly field names.
interface SettingsState {
  rpcEndpoint: string;
  autoRotate: boolean;
  rotationIntervalMin: number;
  killSwitch: boolean;
  gasCeiling: number;
  strictNetwork: boolean;
  pinnedEntry: string;
  pinnedRelay: string;
  pinnedExit: string;
  // Fields not editable in the UI but preserved on round-trip.
  _chainId: number;
}

function toLocal(p: SettingsPayload): SettingsState {
  return {
    rpcEndpoint: p.rpc_url,
    autoRotate: p.auto_rotate,
    rotationIntervalMin: Math.round(p.circuit_rotation_interval_secs / 60),
    killSwitch: p.kill_switch,
    gasCeiling: p.gas_price_ceiling_gwei,
    strictNetwork: p.strict_network_size,
    pinnedEntry: p.preferred_nodes[0] || "",
    pinnedRelay: p.preferred_nodes[1] || "",
    pinnedExit: p.preferred_nodes[2] || "",
    _chainId: p.chain_id,
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
    preferred_nodes: [s.pinnedEntry, s.pinnedRelay, s.pinnedExit],
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
  const [settings, setSettings] = useState<SettingsState>({
    rpcEndpoint: "",
    autoRotate: false,
    rotationIntervalMin: 10,
    killSwitch: true,
    gasCeiling: 10,
    strictNetwork: false,
    pinnedEntry: "",
    pinnedRelay: "",
    pinnedExit: "",
    _chainId: 11155111,
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

      <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Settings take effect on next connection.
      </p>
    </div>
  );
}
