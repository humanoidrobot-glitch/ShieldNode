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
      setNodes(result ?? []);
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
