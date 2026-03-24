import type { NodeInfo } from "./types";

/**
 * Computes a weighted score for a node. Higher is better.
 * Mirrors the Rust `score_node()` in `circuit.rs`.
 *
 * score = 10 * sqrt(stake_eth)     ← 25% weight (revenue accelerator)
 *       + 25 * uptime              ← 25% weight
 *       - 0.001 * price_per_byte   ← 20% weight
 *       - 15 * slash_count^2       ← 15% weight
 *       + 15 * completion_rate     ← 15% weight (session reliability)
 *
 * `node.stake` arrives as wei (1 ETH = 1e18).
 */
export function scoreNode(node: NodeInfo): number {
  const stakeEth = node.stake / 1e18;
  const stakeScore = 10 * Math.sqrt(stakeEth);
  const uptimeScore = 25 * node.uptime;
  const priceScore = 0.001 * node.pricePerByte;
  const slashScore = 15 * node.slashCount ** 2;
  const completionScore = 15 * (node.completionRate ?? 1.0);

  return stakeScore + uptimeScore - priceScore - slashScore + completionScore;
}
