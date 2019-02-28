# apiety

Decrypts network traffic from the game Path of Exile.

> Doesn't work on windows currently, because the packet capturer doesn't capture all packets,
see https://github.com/libpnet/libpnet/issues/349

## Usage

The recommend way to use this is with the provided publisher application. After starting it, it will 
wait for any captured packets on port 20481 and 6112 and send it decrypted with some meta data to 
all connected clients over tcp on localhost:10001. Check `to_buf()` function in `src/packet.rs` to
deserialise it.

## Installation

```
cargo build --release
```

Will produce the binary `./target/release/publisher`

When compiling on windows you need to follow these steps before: https://github.com/libpnet/libpnet#windows

## Acknowledgment

Nia Catlin for her blog post [Reverse engineering the Path of Exile game protocol](https://tbinarii.blogspot.com/2018/05/reverse-engineering-path-of-exile.html) and implementation [exileSniffer](https://github.com/ncatlin/exileSniffer), which was used to figure out how to decrypt the network stream.
