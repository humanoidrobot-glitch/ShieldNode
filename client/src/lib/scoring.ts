import type { NodeInfo } from "./types";

/**
 * Computes a weighted score for a node. Higher is better.
 * Mirrors the Rust `score_node()` in `circuit.rs`.
 *
 * score = 10 * sqrt(stake_eth)     ← dominant factor (revenue accelerator)
 *       + 30 * uptime              ← 0..30 range
 *       - 0.001 * price_per_byte   ← small penalty for expensive nodes
 *       - 20 * slash_count^2       ← harsh penalty for slashed nodes
 *
 * `node.stake` arrives as wei (1 ETH = 1e18).
 */
export function scoreNode(node: NodeInfo): number {
  const stakeEth = node.stake / 1e18;
  const stakeScore = 10 * Math.sqrt(stakeEth);
  const uptimeScore = 30 * node.uptime;
  const priceScore = 0.001 * node.pricePerByte;
  const slashScore = 20 * node.slashCount ** 2;

  return stakeScore + uptimeScore - priceScore - slashScore;
}
