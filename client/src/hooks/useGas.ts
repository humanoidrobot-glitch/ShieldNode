import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { GasLevel } from "../lib/types";

interface UseGasReturn {
  gasPrice: number | null;
  level: GasLevel;
}

function getGasLevel(gwei: number): GasLevel {
  if (gwei < 1) return "low";
  if (gwei <= 5) return "medium";
  return "high";
}

export function useGas(): UseGasReturn {
  const [gasPrice, setGasPrice] = useState<number | null>(null);
  const [level, setLevel] = useState<GasLevel>("low");
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const fetchGas = async () => {
      try {
        const price = await invoke<number>("get_gas_price");
        setGasPrice(price);
        setLevel(getGasLevel(price));
      } catch (err) {
        console.error("Failed to fetch gas price:", err);
      }
    };

    fetchGas();
    intervalRef.current = setInterval(fetchGas, 30_000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, []);

  return { gasPrice, level };
}
