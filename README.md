# VoidHash CPU Miner

Official CPU miner for VoidCoin (VOID) using the VoidHash algorithm.

---

## Download

Get the latest pre-built binaries from the [Releases](https://github.com/VoidHash-Crypto/VoidHash-Miner/releases) page:

| File | Platform |
|------|----------|
| `voidhash-miner-linux-amd64` | Linux 64-bit |
| `voidhash-miner-windows-amd64.exe` | Windows 64-bit |

---

## Usage

### Pool mining (recommended)

```bash
# Linux
./voidhash-miner -user YOUR_VOID_ADDRESS -pool stratum+tcp://pool.voidcoin.network:3532

# Windows
voidhash-miner.exe -user YOUR_VOID_ADDRESS -pool stratum+tcp://pool.voidcoin.network:3532
```

### Solo mining (requires local voidcoind)

```bash
./voidhash-miner -solo -addr YOUR_VOID_ADDRESS
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-user` | (required) | Your VOID payout address |
| `-pool` | `stratum+tcp://pool.voidcoin.network:3532` | Pool stratum address |
| `-pass` | `x` | Worker password |
| `-threads` | all CPU cores | Number of mining threads |
| `-solo` | false | Solo mine via local voidcoind |
| `-addr` | (same as -user) | Payout address for solo mining |
| `-rpchost` | `127.0.0.1` | voidcoind RPC host |
| `-rpcport` | `9332` | voidcoind RPC port |
| `-rpcuser` | `void` | voidcoind RPC username |
| `-rpcpass` | `voidpass` | voidcoind RPC password |

---

## Performance

VoidHash is designed for CPUs. Each hash requires:
- Allocating and filling a **4 MB scratchpad** sequentially
- Walking the scratchpad in a data-dependent pattern
- ~450ms per hash on a modern desktop CPU

GPU miners have minimal advantage due to the sequential dependency chain and
large per-hash memory requirement.

### Recommended hardware

- Modern multi-core CPU with large L3 cache (8 MB+)
- AMD Ryzen / EPYC — excellent
- Intel Core / Xeon — very good
- ARM (Apple M-series, Ampere) — excellent

---

## Building from source

```bash
git clone https://github.com/VoidHash-Crypto/VoidHash-Miner.git
cd VoidHash-Miner
go mod download
go build -o voidhash-miner ./cmd/miner/

# Windows cross-compile from Linux
GOOS=windows GOARCH=amd64 go build -o voidhash-miner.exe ./cmd/miner/
```

---

## Algorithm

VoidHash is **not** SHA3-256. It is a custom 4-step proof-of-work construction:

1. SHA3-256T (tweaked Keccak with domain tag `0xC0DEFA1C0B10CAFE`)
2. Sequential 4 MB scratchpad expansion
3. Data-dependent memory walk
4. Final SHA3-256T digest

See the [VoidHash specification](https://github.com/VoidHash-Crypto/VoidCoin/blob/main/doc/voidhash.md) for full technical details.

---

## License

MIT License
