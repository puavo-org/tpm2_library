Subcrates:

* `tpm2_call` has the goal of providing rustified constants covering TPM2 2.0
  Structures Specification. All the content in this crate operating system
  agnostic.
* `tpm2_cli` is a command-line interface to a TPM 2.0 chip. It is Linux-only
  application using by default /dev/tpmrm0, which is available to users within
  `tss` group in a systemd-based environment.

## Commits

Commit messaged follow
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification.

## Versioning

Versioning follows
[Semantic Versioning](https://semver.org/)
specification.

A new version is created as follows:

```
git tag -s $MAJOR.$MINOR.$PATCH -m $MAJOR.$MINOR.$PATCH
git push origin $MAJOR.$MINOR.$PATCH
```

## Tags

Add a Signed-off-by trailer to the new commits.

## Backwards compatibility

* Patch versions are backwards compatible.
* Minor versions are keptmostly backwards compatible, but we're not going to
  hung up on it.
