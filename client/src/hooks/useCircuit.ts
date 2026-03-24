import { useState, useCallback, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ConnectionStatus, CircuitInfo } from "../lib/types";

interface ConnectionStateResponse {
  status: "Disconnected" | "Connecting" | "Connected";
  rotation_count?: number;
}

interface UseCircuitReturn {
  status: ConnectionStatus;
  error: string | null;
  circuit: CircuitInfo | null;
  rotationCount: number;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}

export function useCircuit(): UseCircuitReturn {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [circuit, setCircuit] = useState<CircuitInfo | null>(null);
  const [rotationCount, setRotationCount] = useState(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Poll circuit info and rotation count while connected.
  useEffect(() => {
    if (status !== "connected") {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }

    let lastRotation = 0;
    const poll = async () => {
      try {
        const state = await invoke<ConnectionStateResponse>("get_status");
        const newCount = state.rotation_count ?? 0;
        if (newCount !== lastRotation) {
          lastRotation = newCount;
          setRotationCount(newCount);
          // Circuit changed — refetch it.
          try {
            const info = await invoke<CircuitInfo | null>("get_circuit");
            setCircuit(info);
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
    };

    pollRef.current = setInterval(poll, 5000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [status]);

  const connect = useCallback(async () => {
    try {
      setError(null);
      setStatus("connecting");
      setRotationCount(0);
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
      setRotationCount(0);
    }
  }, []);

  return { status, error, circuit, rotationCount, connect, disconnect };
}
