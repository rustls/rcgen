extern crate rcgen;

use rcgen::{Certificate, PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION};

fn main() {
	let cert = Certificate::from_alg(PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION);
	println!("{}", cert.serialize_pem());
}
