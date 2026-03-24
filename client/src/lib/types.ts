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
  session_id: string;
  node_id: string;
  bytes_used: number;
  connected_since: number;
}

export type ConnectionStatus = "disconnected" | "connecting" | "connected";

export type GasLevel = "low" | "medium" | "high";

export interface CircuitHop {
  nodeId: string;
  endpoint: string;
  hopIndex: number;
}

export interface CircuitInfo {
  entry: CircuitHop;
  relay: CircuitHop;
  exit: CircuitHop;
}
