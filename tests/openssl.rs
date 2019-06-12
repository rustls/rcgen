extern crate openssl;
extern crate rcgen;

use rcgen::{Certificate};
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req, X509StoreContext};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use openssl::stack::Stack;

mod util;

fn verify_cert(cert :&Certificate) {
	println!("{}", cert.serialize_pem());

	let x509 = X509::from_pem(&cert.serialize_pem().as_bytes()).unwrap();
	let mut builder = X509StoreBuilder::new().unwrap();
	builder.add_cert(x509.clone()).unwrap();

	let store :X509Store = builder.build();
	let mut ctx = X509StoreContext::new().unwrap();
	let mut stack = Stack::new().unwrap();
	stack.push(x509.clone()).unwrap();
	ctx.init(&store, &x509, &stack.as_ref(), |ctx| {
		ctx.verify_cert().unwrap();
		Ok(())
	}).unwrap();
}

fn verify_csr(cert :&Certificate) {
	let csr = cert.serialize_request_pem();
	println!("{}", csr);
	let key = cert.serialize_private_key_der();
	let pkey = PKey::private_key_from_der(&key).unwrap();

	let req = X509Req::from_pem(&cert.serialize_request_pem().as_bytes()).unwrap();
	req.verify(&pkey).unwrap();
}

#[test]
fn test_openssl() {
	let params = util::default_params();
	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
}

#[test]
fn test_request() {
	let params = util::default_params();
	let cert = Certificate::from_params(params).unwrap();

	verify_csr(&cert);
}

#[test]
fn test_openssl_256() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
	verify_csr(&cert);
}

#[test]
fn test_openssl_384() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
	verify_csr(&cert);
}

#[test]
fn test_openssl_25519() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ED25519;

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
	// TODO this fails. Not sure why!
	// https://github.com/openssl/openssl/issues/9134
	//verify_csr(&cert);
}

#[test]
fn test_openssl_25519_v1_given() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ED25519;

	let kp = rcgen::KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V1).unwrap();
	params.key_pair = Some(kp);

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
	// Verify the csr but only on OpenSSL >= 1.1.1
	if openssl::version::number() >= 0x1_01_01_00_f {
		verify_csr(&cert);
	}
}

#[test]
fn test_openssl_25519_v2_given() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ED25519;

	let kp = rcgen::KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V2).unwrap();
	params.key_pair = Some(kp);

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
	// TODO this fails. Not sure why!
	// https://github.com/openssl/openssl/issues/9134
	//verify_csr(&cert);
}

#[test]
fn test_openssl_rsa_given() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_RSA_SHA256;

	let kp = rcgen::KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
	params.key_pair = Some(kp);

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	verify_cert(&cert);
	verify_csr(&cert);
}
