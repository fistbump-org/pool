# pool

A [Fistbump](https://fistbump.org) mining pool and CPU miner written in Swift.

Includes a Stratum v1 pool server with vardiff and PPLNS, and a standalone CPU miner.

## Compatibility

macOS, Linux.

## Prerequisites

- [Swift](https://swift.org/install/) 5.9+
- SQLite3 (`libsqlite3-dev` on Linux)
- A running [fbd](https://github.com/fistbump-org/fbd) node

## Clone

```
git clone https://github.com/fistbump-org/pool.git
cd pool
```

## Build

```
swift build
```

## Run the pool

```
swift run pool --address <your-payout-address>
```

The pool connects to a local fbd node over RPC. Use `--node-url` and `--api-key` to configure the connection.

## Run the miner

```
swift run miner --user <your-payout-address> --port <stratum-port>
```

Use `--threads` to control the number of mining threads (defaults to all cores - 1).

## License

MIT
