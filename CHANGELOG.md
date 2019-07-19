# Changes

## Release 0.5.0 - July 19, 2019

- Update to ring 0.16 and webpki 0.21
- Update to x509-parser 0.5
- Expose an API to get the raw public key of a key pair

## Release 0.4.1 - June 28, 2019

- Allow inspection of `DistinguishedName` via iterators and get functions
- Fix a bug in `is_compatible` not saying false. Contributed by [@fzgregor](https://github.com/fzgregor).
- Extend the public interface of `KeyPair. Contributed by [@fzgregor](https://github.com/fzgregor).

## Release 0.4.0 - June 18, 2019

- Support for user supplied keypairs. Contributed by [@fzgregor](https://github.com/fzgregor).
- Support for signing with user supplied CA certificates. Contributed by [@fzgregor](https://github.com/fzgregor).
- Correct a bug with distinguished name serialization ([PR link](https://github.com/est31/rcgen/pull/13)). Contributed by [@fzgregor](https://github.com/fzgregor).
- Addition of limited (no key generation) RSA support
- Proper error handling with `Result` and our own Error type
- Improvements of the testsuite

## Release 0.3.1 - June 6, 2019

- Ability to disable the dependency on the `pem` crate
- Support for creating CSRs (Certificate Signing Requests). Contributed by [@djc](https://github.com/djc).
- Ability to specify custom extensions for certificates
- Ability to craft `acmeIdentifier` extensions
- Update yasna to 0.3.0

## Release 0.3.0 - May 18, 2019

- Support for CA certificate generation. Contributed by [@djc](https://github.com/djc).
- Support for certificate signing. Contributed by [@djc](https://github.com/djc).
- Support for ED25519 certificates
- Support for SHA-384 certificates
- API cleanups (Future proofing CertificateParams, public constant renames)

## Release 0.2.1 - April 26, 2019

- Updated to pem 0.6

## Release 0.2 - January 10, 2019

- Updated to ring 0.14.0

## Release 0.1 - January 7, 2019

Initial release. Ability to generate self-signed ECDSA keys.
