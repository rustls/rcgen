extern crate openssl;
extern crate rcgen;

use rcgen::{Certificate, CertificateParams, DnType};
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req, X509StoreContext};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use openssl::stack::Stack;

#[test]
fn test_openssl() {
	let mut params = CertificateParams::new(vec![
		"crabs.crabs".to_string(), "localhost".to_string(),
	]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master CA");
	let cert = Certificate::from_params(params);

	println!("{}", cert.serialize_pem());

	// Now verify the certificate.
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

#[test]
fn test_request() {
	let params = CertificateParams::new(vec!["crabs.crabs".to_string(), "localhost".to_string()]);
	let cert = Certificate::from_params(params);

	let key = cert.serialize_private_key_der();
	let pkey = PKey::private_key_from_der(&key).unwrap();

	let req = X509Req::from_pem(&cert.serialize_request_pem().as_bytes()).unwrap();
	req.verify(&pkey).unwrap();
}
