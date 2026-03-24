import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ConnectionStatus, NodeInfo } from "../lib/types";

interface UseCircuitReturn {
  status: ConnectionStatus;
  nodes: NodeInfo[];
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}

export function useCircuit(): UseCircuitReturn {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [nodes, setNodes] = useState<NodeInfo[]>([]);

  const connect = useCallback(async () => {
    try {
      setStatus("connecting");
      const result = await invoke<NodeInfo[]>("connect");
      setNodes(result ?? []);
      setStatus("connected");
    } catch (err) {
      console.error("Failed to connect:", err);
      setStatus("disconnected");
      setNodes([]);
    }
  }, []);

  const disconnect = useCallback(async () => {
    try {
      await invoke("disconnect");
    } catch (err) {
      console.error("Failed to disconnect:", err);
    } finally {
      setStatus("disconnected");
      setNodes([]);
    }
  }, []);

  return { status, nodes, connect, disconnect };
}
