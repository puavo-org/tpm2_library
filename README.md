TPM 2.0 library crate contains:

1. `tpm2_protocol`: a unipolar TPM 2.0 implementation that does not require
   kheap allocator and has zero dependencies.
2. `tpm2_cli`: a command-linne interface for TPM 2.0 chips.

## Development

* Commits: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
* New commits should include a `Signed-off-by` trailer.
* Versioning: [Semantic Versioning](https://semver.org/).

## Licensing

The `tpm2-protocol` library is licensed under the permissive `MIT OR Apache-2.0`
license to allow for wide adoption. The `tpm2-cli` binary and associated tooling
are licensed under the copyleft `GPL-3.0-or-later` license.
