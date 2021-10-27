# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2021-10-27
### Fixed
- Disabled the `num-bigint`, `num-integer`, and `num-traits` default features.
  These dependencies are behind the `alloc` feature flag, but some of their
  default features depend on `std`.

## [0.5.0] - 2021-07-31
### Added
- `no-std` support.
  - `libm` dependency for math operations that aren't available in `core`.
  - Functionality that requires allocations is now behind the (default-enabled)
    `alloc` feature flag.

### Changed
- MSRV is now 1.49.0.
- This crate now depends directly on the `cipher` crate for its traits instead
  of indirectly via the `aes` crate.
- Bumped dependencies to `cipher 0.3`, `block-modes 0.8`, `num-bigint 0.4`.
  - `aes 0.7` is now the minimum compatible crate version.
- `num-bigint`, `num-integer`, and `num-traits` dependencies are now behind the
  (default-enabled) `alloc` feature flag.

### Removed
- Direct dependency on the `aes` crate, enabling it to be dropped in contexts
  where an alternative AES implementation (or alternative compatible block
  cipher) is desired.

## [0.4.0] - 2021-01-27
### Changed
- MSRV is now 1.41.0.
- Bumped dependencies to `aes 0.6`, `block-modes 0.7`.

## [0.3.1] - 2020-08-16
### Changed
- `Numeral::from_bytes` now takes `impl Iterator<Item = u8>` instead of `&[u8]`.

### Fixed
- Subtraction overflow on empty input.

## [0.3.0] - 2020-08-15
### Added
- `Numeral` trait, representing the type used for numeric operations.
- `NumeralString::Num: Numeral` associated type.

### Changed
- MSRV is now 1.36.0.
- Bumped dependencies to `aes 0.5`, `block-modes 0.6`, `num-bigint 0.3`.
- `NumeralString::{num_radix, str_radix}` now use `u32` for the radix and
  `Self:Num` for the numeric form of the numeral string.

## [0.2.0] - 2019-07-22
### Changed
- MSRV is now 1.32.0.
- Bumped dependencies to `aes 0.2`.

## [0.1.0] - 2018-07-31
Initial release.
