/**
 * Wallet connection hook for WalletConnect v2 integration.
 *
 * Handles wallet pairing, address display, and signing request delegation
 * from the Rust backend via Tauri events.
 */

import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type WalletMode = "local" | "walletconnect";

interface WalletState {
  mode: WalletMode;
  address: string | null;
  connected: boolean;
}

interface SigningRequest {
  type: "sendTransaction" | "signTypedData";
  requestId: string;
  to?: string;
  data?: string;
  value?: string;
  digest?: string;
  description?: string;
}

export function useWallet() {
  const [wallet, setWallet] = useState<WalletState>({
    mode: "local",
    address: null,
    connected: false,
  });

  // Load initial wallet mode from backend.
  useEffect(() => {
    invoke<{ mode: WalletMode; address: string | null }>("get_wallet_mode")
      .then((result) => {
        setWallet({
          mode: result.mode,
          address: result.address,
          connected: result.mode === "walletconnect" && !!result.address,
        });
      })
      .catch(console.error);
  }, []);

  // Listen for signing requests from the Rust backend.
  useEffect(() => {
    if (wallet.mode !== "walletconnect" || !wallet.address) return;

    const unlisten = listen<SigningRequest>("signing-request", async (event) => {
      const req = event.payload;
      try {
        if (req.type === "sendTransaction" && req.to && req.data) {
          const accounts = (await window.ethereum?.request({
            method: "eth_requestAccounts",
          })) as string[] | undefined;
          const txHash = await window.ethereum?.request({
            method: "eth_sendTransaction",
            params: [
              {
                from: accounts?.[0],
                to: req.to,
                data: req.data,
                value: req.value || "0x0",
              },
            ],
          });
          await invoke("resolve_signing", {
            response: {
              type: "transactionSent",
              txHash: txHash as string,
              requestId: req.requestId,
            },
          });
        } else if (req.type === "signTypedData" && req.digest) {
          const accounts = (await window.ethereum?.request({
            method: "eth_requestAccounts",
          })) as string[] | undefined;
          const sig = await window.ethereum?.request({
            method: "personal_sign",
            params: [req.digest, accounts?.[0]],
          });
          await invoke("resolve_signing", {
            response: {
              type: "signature",
              signature: sig as string,
              requestId: req.requestId,
            },
          });
        }
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "wallet signing failed";
        await invoke("resolve_signing", {
          response: {
            type: "error",
            message,
            requestId: req.requestId,
          },
        });
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [wallet.mode, wallet.address]);

  const setMode = useCallback(
    async (mode: WalletMode, address?: string) => {
      await invoke("set_wallet_mode", { mode, address: address || null });
      setWallet({
        mode,
        address: address || null,
        connected: mode === "walletconnect" && !!address,
      });
    },
    []
  );

  const connectWallet = useCallback(async () => {
    if (!window.ethereum) {
      throw new Error("No wallet extension detected (install MetaMask)");
    }
    const accounts = (await window.ethereum.request({
      method: "eth_requestAccounts",
    })) as string[];
    if (accounts.length === 0) throw new Error("No accounts returned");
    const address = accounts[0];
    await setMode("walletconnect", address);
  }, [setMode]);

  const disconnectWallet = useCallback(async () => {
    await setMode("local");
  }, [setMode]);

  return {
    wallet,
    connectWallet,
    disconnectWallet,
    setMode,
  };
}

// Extend Window for ethereum provider.
declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
    };
  }
}
