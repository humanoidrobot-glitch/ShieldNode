import type { ConnectionStatus, CircuitInfo } from "../lib/types";

interface CircuitMapProps {
  status: ConnectionStatus;
  circuit: CircuitInfo | null;
  rotationCount?: number;
}

function truncateId(id: string): string {
  if (id.length <= 10) return id;
  return `${id.slice(0, 6)}...${id.slice(-4)}`;
}

interface HopProps {
  label: string;
  sublabel?: string;
  active: boolean;
}

function Hop({ label, sublabel, active }: HopProps) {
  return (
    <div className="flex flex-col items-center gap-1">
      <div
        className="w-16 h-16 rounded-full flex items-center justify-center text-xs font-mono"
        style={{
          background: active ? "var(--card-bg)" : "transparent",
          border: `1px solid ${active ? "var(--accent-green)" : "var(--border-color)"}`,
          color: active ? "var(--accent-green)" : "var(--text-secondary)",
        }}
      >
        {label}
      </div>
      {sublabel && (
        <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
          {sublabel}
        </span>
      )}
    </div>
  );
}

function Arrow({ active }: { active: boolean }) {
  return (
    <div
      className="flex items-center px-1"
      style={{ color: active ? "var(--accent-green)" : "var(--border-color)" }}
    >
      <svg width="32" height="12" viewBox="0 0 32 12" fill="none">
        <line
          x1="0"
          y1="6"
          x2="26"
          y2="6"
          stroke="currentColor"
          strokeWidth="1.5"
        />
        <polyline
          points="22,2 28,6 22,10"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        />
      </svg>
    </div>
  );
}

export function CircuitMap({ status, circuit, rotationCount }: CircuitMapProps) {
  const active = status === "connected";

  // When connected with a 3-hop circuit, show all hops.
  if (active && circuit) {
    return (
      <div
        className="rounded-lg p-4"
        style={{
          background: "var(--card-bg)",
          border: "1px solid var(--border-color)",
        }}
      >
        <div className="flex items-center justify-between mb-3">
          <h3
            className="text-xs font-semibold uppercase tracking-wider"
            style={{ color: "var(--text-secondary)" }}
          >
            Circuit Path
          </h3>
          {rotationCount != null && rotationCount > 0 && (
            <span
              className="text-xs font-mono"
              style={{ color: "var(--accent-green)" }}
            >
              rotated {rotationCount}x
            </span>
          )}
        </div>
        <div className="flex items-center justify-center flex-wrap gap-y-2">
          <Hop label="You" active />
          <Arrow active />
          <Hop label={truncateId(circuit.entry.nodeId)} sublabel="Entry" active />
          <Arrow active />
          <Hop label={truncateId(circuit.relay.nodeId)} sublabel="Relay" active />
          <Arrow active />
          <Hop label={truncateId(circuit.exit.nodeId)} sublabel="Exit" active />
          <Arrow active />
          <Hop label="Internet" active />
        </div>
      </div>
    );
  }

  // Placeholder path (disconnected or single-hop).
  return (
    <div
      className="rounded-lg p-4"
      style={{
        background: "var(--card-bg)",
        border: "1px solid var(--border-color)",
      }}
    >
      <h3
        className="text-xs font-semibold uppercase tracking-wider mb-3"
        style={{ color: "var(--text-secondary)" }}
      >
        Circuit Path
      </h3>
      <div className="flex items-center justify-center">
        <Hop label="You" active={active} />
        <Arrow active={active} />
        <Hop label="Entry" active={active} />
        <Arrow active={active} />
        <Hop label="Relay" active={active} />
        <Arrow active={active} />
        <Hop label="Exit" active={active} />
        <Arrow active={active} />
        <Hop label="Internet" active={active} />
      </div>
    </div>
  );
}
