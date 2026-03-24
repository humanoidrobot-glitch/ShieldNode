import type { SessionInfo } from "../lib/types";

interface SessionCostProps {
  session: SessionInfo | null;
  loading: boolean;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function SessionCost({ session, loading }: SessionCostProps) {
  if (!session) {
    return (
      <div
        className="rounded-lg p-4"
        style={{
          background: "var(--card-bg)",
          border: "1px solid var(--border-color)",
        }}
      >
        <h3
          className="text-xs font-semibold uppercase tracking-wider mb-2"
          style={{ color: "var(--text-secondary)" }}
        >
          Session
        </h3>
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          No active session
        </p>
      </div>
    );
  }

  const elapsed = Math.floor(Date.now() / 1000) - session.startTime;
  // Rough cost estimate: assume a flat rate placeholder
  const estimatedCost = session.bytesUsed * 1e-12; // simplified placeholder

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
        Session {loading && <span className="ml-1 opacity-50">(updating...)</span>}
      </h3>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Deposit
          </p>
          <p className="text-sm font-mono">{session.deposit.toFixed(6)} ETH</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Data Used
          </p>
          <p className="text-sm font-mono">{formatBytes(session.bytesUsed)}</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Est. Cost
          </p>
          <p className="text-sm font-mono">{estimatedCost.toFixed(8)} ETH</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Duration
          </p>
          <p className="text-sm font-mono">{formatDuration(elapsed)}</p>
        </div>
      </div>
    </div>
  );
}
