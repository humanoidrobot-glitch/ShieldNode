import type { NodeInfo, SessionInfo } from "../lib/types";

interface SessionCostProps {
  session: SessionInfo | null;
  loading: boolean;
  nodes: NodeInfo[];
  gasPrice: number | null;
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

// Gas units for on-chain operations (from CLAUDE.md gas budget)
const GAS_OPEN_SESSION = 100_000;
const GAS_SETTLE_SESSION = 120_000;
const ESTIMATE_BYTES_1GB = 1024 * 1024 * 1024;

/** Estimate per-session gas cost in ETH at the given Gwei price. */
function estimateGasCostEth(gasPriceGwei: number): number {
  const totalGas = GAS_OPEN_SESSION + GAS_SETTLE_SESSION;
  return totalGas * gasPriceGwei * 1e-9;
}

/** Estimate bandwidth cost in ETH for a given data amount and price-per-byte. */
function estimateBandwidthCostEth(bytesEstimate: number, avgPricePerByte: number): number {
  // pricePerByte is in wei-like units; convert to ETH
  return bytesEstimate * avgPricePerByte * 1e-18;
}

/** Compute median price-per-byte from available nodes. */
function medianPrice(nodes: NodeInfo[]): number {
  if (nodes.length === 0) return 0;
  const prices = nodes.map((n) => n.pricePerByte).sort((a, b) => a - b);
  const mid = Math.floor(prices.length / 2);
  return prices.length % 2 === 0 ? (prices[mid - 1] + prices[mid]) / 2 : prices[mid];
}

export function SessionCost({ session, loading, nodes, gasPrice }: SessionCostProps) {
  if (!session) {
    const price = medianPrice(nodes);
    const hasData = nodes.length > 0 && gasPrice !== null;
    const gasCost = gasPrice !== null ? estimateGasCostEth(gasPrice) : 0;
    const bwCost = estimateBandwidthCostEth(ESTIMATE_BYTES_1GB, price);
    const totalCost = gasCost + bwCost;

    return (
      <div
        className="rounded-lg p-4"
        style={{ background: "var(--card-bg)", border: "1px solid var(--border-color)" }}
      >
        <h3
          className="text-xs font-semibold uppercase tracking-wider mb-3"
          style={{ color: "var(--text-secondary)" }}
        >
          Estimated Cost
        </h3>
        {hasData ? (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Per 1 GB</p>
              <p className="text-sm font-mono">{bwCost.toFixed(6)} ETH</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Gas (open+settle)</p>
              <p className="text-sm font-mono">{gasCost.toFixed(6)} ETH</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Total (1 GB)</p>
              <p className="text-sm font-mono">{totalCost.toFixed(6)} ETH</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Median price</p>
              <p className="text-sm font-mono">{price} wei/byte</p>
            </div>
          </div>
        ) : (
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            {nodes.length === 0 ? "Loading nodes..." : "Loading gas price..."}
          </p>
        )}
      </div>
    );
  }

  const elapsed = Math.floor(Date.now() / 1000) - session.connected_since;
  const estimatedCost = session.bytes_used * 1e-12;

  return (
    <div
      className="rounded-lg p-4"
      style={{ background: "var(--card-bg)", border: "1px solid var(--border-color)" }}
    >
      <h3
        className="text-xs font-semibold uppercase tracking-wider mb-3"
        style={{ color: "var(--text-secondary)" }}
      >
        Session {loading && <span className="ml-1 opacity-50">(updating...)</span>}
      </h3>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Data Used</p>
          <p className="text-sm font-mono">{formatBytes(session.bytes_used)}</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Duration</p>
          <p className="text-sm font-mono">{formatDuration(elapsed)}</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Est. Cost</p>
          <p className="text-sm font-mono">{estimatedCost.toFixed(8)} ETH</p>
        </div>
        <div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>Node</p>
          <p className="text-sm font-mono">{session.node_id.slice(0, 12)}...</p>
        </div>
      </div>
    </div>
  );
}
