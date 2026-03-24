export interface NodeInfo {
  nodeId: string;
  publicKey: string;
  endpoint: string;
  stake: number;
  uptime: number;
  pricePerByte: number;
  slashCount: number;
}

export interface SessionInfo {
  sessionId: string;
  nodeId: string;
  deposit: number;
  bytesUsed: number;
  startTime: number;
  status: "active" | "closed" | "disputed";
}

export type ConnectionStatus = "disconnected" | "connecting" | "connected";

export type GasLevel = "low" | "medium" | "high";
