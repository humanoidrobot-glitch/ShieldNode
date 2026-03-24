/** Sepolia testnet contract addresses */
export const NODE_REGISTRY_ADDRESS =
  "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11" as const;
export const SESSION_SETTLEMENT_ADDRESS =
  "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959" as const;
export const SLASHING_ORACLE_ADDRESS =
  "0x28E5059F61F458a86c5318C63b8b7688BA678FeD" as const;
export const TREASURY_ADDRESS =
  "0xaE76fF930d1137b4a10e76285d82A5e40FF0619f" as const;

/** Minimal ABI for NodeRegistry — only functions the client calls */
export const nodeRegistryAbi = [
  {
    name: "getNode",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nodeId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "owner", type: "address" },
          { name: "publicKey", type: "bytes" },
          { name: "endpoint", type: "string" },
          { name: "stake", type: "uint256" },
          { name: "uptime", type: "uint64" },
          { name: "pricePerByte", type: "uint256" },
          { name: "slashCount", type: "uint32" },
          { name: "active", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "getActiveNodes",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    name: "nodeCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

/** Minimal ABI for SessionSettlement */
export const sessionSettlementAbi = [
  {
    name: "openSession",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "nodeId", type: "bytes32" },
      { name: "deposit", type: "uint256" },
    ],
    outputs: [{ name: "sessionId", type: "bytes32" }],
  },
  {
    name: "closeSession",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sessionId", type: "bytes32" },
      { name: "cumulativeBytes", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "getSession",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "sessionId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "client", type: "address" },
          { name: "nodeId", type: "bytes32" },
          { name: "deposit", type: "uint256" },
          { name: "bytesUsed", type: "uint256" },
          { name: "startTime", type: "uint64" },
          { name: "status", type: "uint8" },
        ],
      },
    ],
  },
] as const;
