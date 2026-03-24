import { useState, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { NodeInfo } from "../lib/types";

interface UseNodesReturn {
  nodes: NodeInfo[];
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

export function useNodes(): UseNodesReturn {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<NodeInfo[]>("get_nodes");
      setNodes((prev) => {
        const next = result ?? [];
        if (prev.length === next.length && prev.every((n, i) => n.nodeId === next[i].nodeId && n.pricePerByte === next[i].pricePerByte && n.stake === next[i].stake)) {
          return prev;
        }
        return next;
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { nodes, loading, error, refresh };
}
