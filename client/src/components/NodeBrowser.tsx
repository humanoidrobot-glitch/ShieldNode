import { useState, useMemo } from "react";
import type { NodeInfo } from "../lib/types";
import { scoreNode } from "../lib/scoring";

interface NodeBrowserProps {
  nodes: NodeInfo[];
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

type SortKey = "nodeId" | "stake" | "uptime" | "pricePerByte" | "slashCount" | "score";
type SortDir = "asc" | "desc";

function truncateId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-4)}`;
}

export function NodeBrowser({ nodes, loading, error, onRefresh }: NodeBrowserProps) {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return nodes.filter(
      (n) =>
        n.nodeId.toLowerCase().includes(q) ||
        n.endpoint.toLowerCase().includes(q),
    );
  }, [nodes, search]);

  const scored = useMemo(
    () => filtered.map((n) => ({ node: n, score: scoreNode(n) })),
    [filtered],
  );

  const sorted = useMemo(() => {
    return [...scored].sort((a, b) => {
      let aVal: number;
      let bVal: number;

      if (sortKey === "score") {
        aVal = a.score;
        bVal = b.score;
      } else if (sortKey === "nodeId") {
        return sortDir === "asc"
          ? a.node.nodeId.localeCompare(b.node.nodeId)
          : b.node.nodeId.localeCompare(a.node.nodeId);
      } else {
        aVal = a.node[sortKey];
        bVal = b.node[sortKey];
      }

      return sortDir === "asc" ? aVal - bVal : bVal - aVal;
    });
  }, [scored, sortKey, sortDir]);

  const columns: { key: SortKey; label: string }[] = [
    { key: "nodeId", label: "Node ID" },
    { key: "stake", label: "Stake (ETH)" },
    { key: "uptime", label: "Uptime (%)" },
    { key: "pricePerByte", label: "Price/GB" },
    { key: "slashCount", label: "Slashes" },
    { key: "score", label: "Score" },
  ];

  return (
    <div>
      <div className="flex items-center gap-3 mb-3">
        <input
          type="text"
          placeholder="Search nodes..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 px-3 py-2 rounded text-sm"
          style={{
            background: "var(--bg-dark)",
            border: "1px solid var(--border-color)",
            color: "var(--text-primary)",
          }}
        />
        <button
          onClick={onRefresh}
          disabled={loading}
          className="px-3 py-2 rounded text-sm font-medium cursor-pointer"
          style={{
            background: "var(--border-color)",
            color: "var(--text-primary)",
          }}
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {error && (
        <p className="text-sm mb-2" style={{ color: "var(--accent-red)" }}>
          {error}
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border-color)" }}>
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  className="px-3 py-2 text-left cursor-pointer select-none font-medium"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {col.label}
                  {sortKey === col.key && (
                    <span className="ml-1">{sortDir === "asc" ? "^" : "v"}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-3 py-6 text-center"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {loading ? "Loading nodes..." : "No nodes found"}
                </td>
              </tr>
            ) : (
              sorted.map(({ node, score }) => (
                <tr
                  key={node.nodeId}
                  className="hover:opacity-80 transition-opacity"
                  style={{ borderBottom: "1px solid var(--border-color)" }}
                >
                  <td className="px-3 py-2 font-mono text-xs">
                    {truncateId(node.nodeId)}
                  </td>
                  <td className="px-3 py-2">{node.stake.toFixed(2)}</td>
                  <td className="px-3 py-2">{node.uptime.toFixed(1)}</td>
                  <td className="px-3 py-2">
                    {(node.pricePerByte * 1e9).toFixed(4)} Gwei
                  </td>
                  <td className="px-3 py-2">{node.slashCount}</td>
                  <td
                    className="px-3 py-2 font-medium"
                    style={{ color: "var(--accent-green)" }}
                  >
                    {score.toFixed(3)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
