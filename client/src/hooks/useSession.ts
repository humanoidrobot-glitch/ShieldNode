import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { SessionInfo, ConnectionStatus } from "../lib/types";

interface UseSessionReturn {
  session: SessionInfo | null;
  loading: boolean;
}

export function useSession(connectionStatus: ConnectionStatus): UseSessionReturn {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (connectionStatus !== "connected") {
      setSession(null);
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      return;
    }

    const fetchSession = async () => {
      setLoading(true);
      try {
        const result = await invoke<SessionInfo | null>("get_session");
        setSession((prev) => {
          if (!result) return null;
          if (prev && prev.session_id === result.session_id && prev.bytes_used === result.bytes_used) {
            return prev;
          }
          return result;
        });
      } catch (err) {
        console.error("Failed to fetch session:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchSession();
    intervalRef.current = setInterval(fetchSession, 5000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [connectionStatus]);

  return { session, loading };
}
