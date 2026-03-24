import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ConnectionStatus, CircuitInfo } from "../lib/types";

interface UseCircuitReturn {
  status: ConnectionStatus;
  error: string | null;
  circuit: CircuitInfo | null;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}

export function useCircuit(): UseCircuitReturn {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [circuit, setCircuit] = useState<CircuitInfo | null>(null);

  const connect = useCallback(async () => {
    try {
      setError(null);
      setStatus("connecting");
      await invoke<string>("connect");
      setStatus("connected");

      // Fetch circuit info after successful connection.
      try {
        const info = await invoke<CircuitInfo | null>("get_circuit");
        setCircuit(info);
      } catch {
        // Non-fatal — single-hop connections won't have circuit info.
        setCircuit(null);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      setStatus("disconnected");
      setCircuit(null);
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
      setCircuit(null);
    }
  }, []);

  return { status, error, circuit, connect, disconnect };
}
