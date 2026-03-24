/** EIP-712 domain and types for bandwidth receipt signing. */

export const EIP712_DOMAIN = {
  name: "ShieldNode",
  version: "1",
  // Sepolia chain ID
  chainId: 11155111,
  // Placeholder — will be replaced with the deployed SessionSettlement address
  verifyingContract: "0x0000000000000000000000000000000000000002" as `0x${string}`,
} as const;

export const BANDWIDTH_RECEIPT_TYPES = {
  BandwidthReceipt: [
    { name: "sessionId", type: "bytes32" },
    { name: "cumulativeBytes", type: "uint256" },
    { name: "timestamp", type: "uint256" },
  ],
} as const;

export interface BandwidthReceipt {
  sessionId: `0x${string}`;
  cumulativeBytes: bigint;
  timestamp: bigint;
}
