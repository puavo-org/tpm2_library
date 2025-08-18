# TPM 2.0 library crate

1. `tpm2_protocol`: a unipolar `no_std` TPM 2.0 implementation that does not
   require heap allocator and has zero dependencies.
2. `tpm2sh`: a command-line interface for TPM 2.0 chips.

## Development

* Commits: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
* New commits should include a `Signed-off-by` trailer.
* Versioning: [Semantic Versioning](https://semver.org/).

### Build System

The project provides a `Makefile` with `make test` target. The unit test is by
design compiling with GNU make and rustc, and it outputs kselftest compatible
exit codes. This ensures that is code that can be imported to Linux kernel.

## Licensing

The `tpm2-protocol` library is licensed under the permissive `MIT OR Apache-2.0`
license to allow for wide adoption. The `tpm2-cli` binary and associated tooling
are licensed under the copyleft `GPL-3.0-or-later` license.


