# rustls-cert-gen

`rustls-cert-gen` is a tool to generate TLS certificates. In its
current state it will generate a Root CA and an end-entity
certificate, along with private keys. The end-entity certificate will
be signed by the Root CA.

## Usage
Having compiled the binary you can simply pass a path to output
generated files.

	cargo run -- -o output/dir

In the output directory you will find these files:

  * `cert.pem`  (end-entity's X.509 certificate, signed by `root-ca`'s key)
  * `cert.key.pem` (end-entity's private key)
  * `root-ca.pem` (ca's self-signed x.509 certificate)

For a complete list of supported options:

	rustls-cert-gen --help

## FAQ

#### What signature schemes are available?

  * `pkcs_ecdsa_p256_sha256`
  * `pkcs_ecdsa_p384_sha384`
  * `pkcs_ed25519`
