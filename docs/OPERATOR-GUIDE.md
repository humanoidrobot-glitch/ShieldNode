# ShieldNode Operator Guide

Run a ShieldNode relay and earn ETH for routing encrypted traffic.

## Prerequisites

- Docker and Docker Compose
- An Ethereum wallet with:
  - 0.1 ETH minimum for staking (held in NodeRegistry)
  - ~0.01 ETH for gas (registration + heartbeats)
- An Ethereum RPC endpoint (Alchemy, Infura, or self-hosted Reth/Geth)

## Quick Start

```bash
cd node/

# 1. Copy the sample config and fill in your details
cp config.toml my-config.toml
# Edit my-config.toml — set ethereum_rpc and operator_private_key

# 2. Build the image
docker compose build

# 3. Register your node on-chain (one-time, stakes 0.1 ETH)
docker compose run --rm shieldnode --config /data/config.toml --register

# 4. Start the relay
docker compose up -d
```

Your node is now:
- Routing encrypted relay traffic on port 51821/UDP
- Accepting WireGuard tunnels on port 51820/UDP
- Discoverable via libp2p on port 4001/TCP
- Serving health/metrics on port 9090/TCP
- Sending on-chain heartbeats every 6 hours

## Configuration

Edit `config.toml` before starting. Key fields:

| Field | Required | Description |
|-------|----------|-------------|
| `ethereum_rpc` | Yes | Your RPC endpoint URL |
| `operator_private_key` | Yes | Hex-encoded wallet key (pays gas, holds stake) |
| `stake_address` | No | NodeRegistry contract (defaults to Sepolia) |
| `settlement_address` | No | SessionSettlement contract |
| `price_per_byte` | No | Your pricing (default: 2000 wei/byte) |
| `exit_mode` | No | Enable exit node (default: false, relay only) |

See `config.toml` for all options with descriptions.

**Security:** Never commit `operator_private_key` to version control. Use a dedicated hot wallet with only the funds needed for staking and gas.

## Verify It's Running

```bash
# Health check
curl http://localhost:9090/health

# Bandwidth metrics
curl http://localhost:9090/metrics

# Active sessions
curl http://localhost:9090/sessions

# Logs
docker compose logs -f shieldnode
```

## Exit Node Mode

Exit nodes earn 2x revenue (50% vs 25% split) but expose your IP as the traffic destination. To enable:

1. Set `exit_mode = true` in `config.toml`
2. Uncomment the `cap_add` and `devices` sections in `docker-compose.yml`
3. Restart: `docker compose up -d`

Exit mode requires `NET_ADMIN` capability for TUN device creation.

## Ports

Ensure these are open in your firewall and forwarded if behind NAT:

| Port | Protocol | Purpose |
|------|----------|---------|
| 51820 | UDP | WireGuard tunnel |
| 51821 | UDP | Relay (multi-hop forwarding) |
| 4001 | TCP | libp2p peer discovery |
| 9090 | TCP | Metrics API (keep firewalled or local-only) |

**Note:** Port 9090 is bound to localhost by default. To expose it to a monitoring network, change `127.0.0.1:9090:9090/tcp` in `docker-compose.yml`.

### NAT / Port Forwarding

ShieldNode relay nodes **must** be reachable from the internet on UDP ports 51820 and 51821. If your node is behind a NAT (home router, cloud VPC), you must configure port forwarding:

**Home router:**
1. Log into your router admin panel (typically 192.168.1.1)
2. Find "Port Forwarding" or "Virtual Server" section
3. Forward UDP 51820 and UDP 51821 to your node's local IP
4. Ensure your ISP does not use Carrier-Grade NAT (CGNAT) — if they do, contact them for a public IP or use a VPS

**Cloud providers (AWS, GCP, etc.):**
- Add inbound UDP rules for ports 51820 and 51821 to your security group / firewall
- Cloud instances typically have direct public IPs — no additional NAT config needed

**Verification:**
```bash
# From another machine, check if your node is reachable:
nc -zuv YOUR_PUBLIC_IP 51820
nc -zuv YOUR_PUBLIC_IP 51821
```

**UPnP / STUN:** Automatic NAT traversal (UPnP, STUN hole-punching) is on the roadmap but not yet implemented. For now, manual port forwarding is required.

## Economics

Revenue depends on traffic routed through your node:

| Role | Revenue Share | Risk |
|------|--------------|------|
| Entry node | 25% | Sees client IP (not destination) |
| Relay node | 25% | Sees neither client nor destination |
| Exit node | 50% | Sees destination IP (not client) |

**Costs:**
- 0.1 ETH staked (illiquid during operation, 7-day unstaking cooldown)
- ~$2.40/month for heartbeat gas (at 0.2 Gwei)
- Server hosting + bandwidth

Higher stake improves your node's score and attracts more sessions. 0.5-1 ETH is noticeably better than the 0.1 ETH minimum.

## Updating

```bash
cd node/
git pull
docker compose build
docker compose up -d
```

Your node key and stake persist across updates via the Docker volume.

## Stopping / Unstaking

```bash
# Stop the relay
docker compose down

# Your stake remains locked for 7 days after you stop sending heartbeats.
# After the cooldown, unstake via the NodeRegistry contract directly.
```

## Troubleshooting

**"failed to bind" errors:** Another process is using the port. Change the port in `config.toml` and update `docker-compose.yml` port mappings to match.

**No heartbeats:** Check that `operator_private_key` and `ethereum_rpc` are set correctly, and the wallet has ETH for gas.

**TUN device errors (exit mode):** Ensure `cap_add: NET_ADMIN` and `/dev/net/tun` device are uncommented in `docker-compose.yml`.

**libp2p discovery warnings:** Non-fatal. The node continues to operate; clients can still find you via the on-chain registry.
