# VEXIL protobuf contract

`vexil.proto` is a typed, cross-language interface to the VEXIL operations — the
same ones the WASM and C-ABI bridges expose. Use it to talk to a VEXIL bridge
from any language with a protobuf/gRPC stack.

It is **not** a second wire format: ciphertexts, keys, bundles and session
messages stay opaque `bytes` whose canonical byte layout is the TLV format in
[../PROTOCOL.md](../PROTOCOL.md). The proto only frames the request/response and
transport.

## Generate stubs

```sh
# Rust (prost / tonic)
protoc --prost_out=src/ proto/vexil.proto

# Node / TypeScript (ts-proto or protobufjs)
protoc --ts_proto_out=src/ proto/vexil.proto

# Go, Python, ...
protoc --go_out=. proto/vexil.proto
```

## Shape
- `Suite` / `Mode` enums mirror the on-wire bytes.
- At-rest: `EncryptPassword`, `DecryptPassword`, `Keygen`, `Seal`, `Open`,
  `Sign`, `Verify`.
- Live session: `PreKeyBundle`, `PreKeySecrets`, `Handshake`, `SessionMessage`.
- Groups: `SenderKeyDistribution`, `GroupMessage`.
- A `service Vexil { ... }` for a gRPC-style bridge over the WASM/FFI/native API.
