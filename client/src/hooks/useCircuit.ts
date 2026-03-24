import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ConnectionStatus } from "../lib/types";

interface UseCircuitReturn {
  status: ConnectionStatus;
  error: string | null;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}

export function useCircuit(): UseCircuitReturn {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);

  const connect = useCallback(async () => {
    try {
      setError(null);
      setStatus("connecting");
      await invoke<string>("connect");
      setStatus("connected");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      setStatus("disconnected");
    }
  }, []);

  const disconnect = useCallback(async () => {
    try {
      setError(null);
      await invoke<string>("disconnect");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setStatus("disconnected");
    }
  }, []);

  return { status, error, connect, disconnect };
}
