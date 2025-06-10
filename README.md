# vnc-rs

[![Build](https://github.com/HsuJv/vnc-rs/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/HsuJv/vnc-rs/actions/workflows/build.yml)
[![API Docs](https://docs.rs/vnc-rs/badge.svg)](https://docs.rs/vnc-rs/latest/vnc)
[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![LICENSE](https://img.shields.io/badge/license-Apache-blue.svg)](LICENSE-APACHE)

## New Features

- [x] Support VeNCrypt x509 TLS encrypt
- [ ] Support RSA-AES/RSA-AES-256 encrypt

## Description

An async implementation of VNC client side protocol

Worked as a protocol engine which consumes input event from the frontend and the vnc server and generate event to let the frontend render.

Can be used on both the OS and WASI.

A simple client usage can be found at [vncviewer](https://github.com/plos-clan/vnc-rs/blob/main/examples/vncviewer.rs).

A simple web assembly client can be found at [webvnc](https://github.com/HsuJv/webgateway/tree/main/webvnc/src).

## Why this

I initially intended to write a wasm version of vnc, and yes, a wasm version has been implemented as per the [VNC Core RFC](https://www.rfc-editor.org/rfc/rfc6143.html)

During the implementation I found an existing respository [whitequark's rust vnc](https://github.com/whitequark/rust-vnc). Which is too coupled to the OS (requring multi-thread and `std::io::TcpStream`) to migrate to a wasm application. But thanks to whitequark's work, I finally worked out how to do VncAuth on the client side.

Looking back [whitequark's rust vnc](https://github.com/whitequark/rust-vnc) and [my old webvnc](https://github.com/HsuJv/webgateway/tree/a031a9d0472677cb17cc269abdd1cbc7349582bc/webvnc),  I didn't think it would be appropriate to put the parsing of the vnc protocol directly into the application. So I separated the engine part and the result is this crate.

It is intended to be a more compatible vnc engine that can be built for both OS applications and Wasm applications. So I did my best to minimise dependencies. However, asynchrony is necessary for websocket processes and in the end I chose `tokio` over `async_std`, which makes it a bit incompatible.

## Encodings

I've only tried video streaming from tight vnc server on win10/ubuntu 20.04 and the built-in vnc server on macos 12.6 (with password login turned on)

Tight encoding, Zrle encoding & Raw encoding all work fine.

But without any idea, when I send setClientEncoding(TRLE) to the vnc server it response with raw rectangles without any encoding. So Trle encoding is not tested. But the trle decoding routine shall be right since it was split from zrle routine

According to the RFC, the [Hextile Encoding](https://www.rfc-editor.org/rfc/rfc6143.html#section-7.7.4) and [RRE Encoding](https://www.rfc-editor.org/rfc/rfc6143.html#section-7.7.3) are both obsolescent, so I didn't try to implement them.

## Acknowledgements

[whitequark's rust vnc](https://github.com/whitequark/rust-vnc).

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
