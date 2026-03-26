# ZK-VM Proof of Correct Relay Forwarding

Proves that a relay node correctly executed `process_relay_packet()` on a
specific packet — decrypted the Sphinx layer and produced the correct output.

## How It Works

1. **Challenger** selects a packet from the relay's committed packet log
2. **Node** provides the packet, session key, and nonce as private inputs
3. **ZK-VM** executes `process_relay_packet()` inside RISC Zero's zkVM
4. **Proof** attests: "this input produced this output via honest execution"
5. **Verifier** checks the proof on-chain — if invalid, the node is slashed

## What This Proves

The proof demonstrates that:
- The relay correctly decrypted the Sphinx layer (ChaCha20-Poly1305)
- The correct next_hop was extracted from the decrypted payload
- The inner payload was forwarded without modification
- No other computation occurred (the guest program IS the relay function)

## What This Does NOT Prove

- It does not prove the node didn't also copy the packet elsewhere (logging)
  → That's the execution trace proof (Phase 6+)
- It does not prove the node forwarded every packet it received
  → Random sampling catches drop rates probabilistically

## Project Structure

```
zkvm/
├── guest/src/main.rs    # The program executed inside the ZK-VM
├── host/src/main.rs     # The prover that generates the proof
├── methods/             # Build artifacts (generated)
└── README.md
```

## Dependencies

- [RISC Zero](https://www.risczero.com/) zkVM
- `risc0-zkvm` crate for guest/host
- `chacha20poly1305` for the decrypt operation inside the guest
