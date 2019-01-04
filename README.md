# rcgen

Simple Rust library to generate X.509 certificates.

## Trying it out

It's still a bit early on, but you can already do this:

```
cargo run > test.pem
openssl x509 -in test.pem -text -noout
```

For debugging, you can paste the contents of test.crt into [this](https://lapo.it/asn1js/) very helpful service.

### License
[license]: #license

This crate is distributed under the terms of both the MIT license
and the Apache License (Version 2.0), at your option.

See [LICENSE](LICENSE) for details.

#### License of your contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
