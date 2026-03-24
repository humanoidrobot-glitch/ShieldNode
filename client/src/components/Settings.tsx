import { useState } from "react";

interface SettingsState {
  rpcEndpoint: string;
  autoRotate: boolean;
  killSwitch: boolean;
  gasCeiling: number;
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
    rpcEndpoint: "https://rpc.sepolia.org",
    autoRotate: false,
    killSwitch: true,
    gasCeiling: 10,
  });

  const update = <K extends keyof SettingsState>(key: K, value: SettingsState[K]) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

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
        description="Periodically switch to a new node"
        checked={settings.autoRotate}
        onChange={(v) => update("autoRotate", v)}
      />

      <Toggle
        label="Kill switch"
        description="Block traffic if VPN disconnects"
        checked={settings.killSwitch}
        onChange={(v) => update("killSwitch", v)}
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
    </div>
  );
}
