# EME block cipher mode for Rust

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

**EME** (ECB-Mix-ECB) is a tweakable enciphering scheme introduced by Shai Halevi and Phillip Rogaway in 2003.

This implementation is based on https://github.com/rfjakob/eme and https://github.com/jmesmon/rust-eme.

It is generic over the used cipher and padding, but only supports ciphers with a 128 bit (16 Byte) block size.

## Minimum Supported Rust Version

This crate will follow the MSRV of the [RustCrypto][1] project, which  currently requires Rust **1.41** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.


[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/eme-mode.svg
[crate-link]: https://crates.io/crates/eme-mode
[docs-image]: https://docs.rs/eme-mode/badge.svg
[docs-link]: https://docs.rs/eme-mode/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[build-image]: https://github.com/B4dM4n/eme-mode-rs/workflows/eme-mode/badge.svg?branch=master&event=push
[build-link]: https://github.com/B4dM4n/eme-mode-rs/actions?query=workflow%3Aeme-mode

[//]: # (general links)

[1]: https://github.com/RustCrypto
