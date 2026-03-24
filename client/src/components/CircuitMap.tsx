import type { ConnectionStatus, NodeInfo } from "../lib/types";

interface CircuitMapProps {
  status: ConnectionStatus;
  nodes: NodeInfo[];
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

export function CircuitMap({ status, nodes }: CircuitMapProps) {
  const active = status === "connected";
  const exitNode = nodes.length > 0 ? nodes[0] : null;

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
        <Hop
          label={exitNode ? truncateId(exitNode.nodeId) : "Node"}
          sublabel={exitNode ? `${exitNode.uptime}% up` : undefined}
          active={active}
        />
        <Arrow active={active} />
        <Hop label="Internet" active={active} />
      </div>
    </div>
  );
}
