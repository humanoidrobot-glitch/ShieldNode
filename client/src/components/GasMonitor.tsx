import type { GasLevel } from "../lib/types";

interface GasMonitorProps {
  gasPrice: number | null;
  level: GasLevel;
}

const LEVEL_COLORS: Record<GasLevel, string> = {
  low: "var(--accent-green)",
  medium: "#f59e0b",
  high: "var(--accent-red)",
};

const LEVEL_LABELS: Record<GasLevel, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
};

export function GasMonitor({ gasPrice, level }: GasMonitorProps) {
  const color = LEVEL_COLORS[level];

  return (
    <div
      className="rounded-lg p-4 flex items-center gap-3"
      style={{
        background: "var(--card-bg)",
        border: "1px solid var(--border-color)",
      }}
    >
      <div
        className="w-3 h-3 rounded-full shrink-0"
        style={{ background: color }}
      />
      <div className="flex-1 min-w-0">
        <h3
          className="text-xs font-semibold uppercase tracking-wider"
          style={{ color: "var(--text-secondary)" }}
        >
          L1 Gas
        </h3>
        <p className="text-sm font-mono" style={{ color }}>
          {gasPrice !== null ? `${gasPrice.toFixed(2)} Gwei` : "--"}
          <span
            className="ml-2 text-xs font-sans"
            style={{ color: "var(--text-secondary)" }}
          >
            {LEVEL_LABELS[level]}
          </span>
        </p>
      </div>
    </div>
  );
}
