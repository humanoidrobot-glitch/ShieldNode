import type { NodeInfo } from "./types";

/**
 * Computes a weighted score for a node. Higher is better.
 *
 * Weights:
 *   - Uptime:      30%  (0-100 maps linearly)
 *   - Stake:       25%  (log-scaled, more stake = more trustworthy)
 *   - Price:       25%  (inverse — cheaper is better)
 *   - Slash count: 20%  (penalty — fewer slashes = better)
 */
export function scoreNode(node: NodeInfo): number {
  // Uptime: already 0-100, normalize to 0-1
  const uptimeScore = node.uptime / 100;

  // Stake: log scale, clamp at a reasonable range
  // Assume stake is in ETH. log(1 ETH) ~ 0, log(32 ETH) ~ 3.47
  const stakeScore = Math.min(Math.log(Math.max(node.stake, 0.01) + 1) / 4, 1);

  // Price: inverse — lower price = higher score
  // Normalize assuming price range of 0 to 1e-9 ETH per byte
  const maxPrice = 1e-9;
  const priceScore = Math.max(
    1 - node.pricePerByte / maxPrice,
    0,
  );

  // Slash penalty: 0 slashes = 1.0, each slash reduces score
  const slashScore = Math.max(1 - node.slashCount * 0.2, 0);

  return (
    uptimeScore * 0.3 +
    stakeScore * 0.25 +
    priceScore * 0.25 +
    slashScore * 0.2
  );
}
