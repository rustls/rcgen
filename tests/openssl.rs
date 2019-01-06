extern crate openssl;
extern crate rcgen;

use rcgen::{Certificate, CertificateParams,
	DistinguishedName, DnType,
	PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION,
	date_time_ymd};

use openssl::x509::{X509, X509StoreContext};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use openssl::stack::Stack;

#[test]
fn test_openssl() {
	let not_before = date_time_ymd(1900, 01, 01);
	let not_after = date_time_ymd(1901, 01, 01);
	let mut distinguished_name = DistinguishedName::new();
	distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	distinguished_name.push(DnType::CommonName, "Master CA");
	let params = CertificateParams {
		alg : PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION,
		not_before,
		not_after,
		serial_number : None,
		subject_alt_names : vec!["crabs.crabs".to_string(), "localhost".to_string()],
		distinguished_name,
	};
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
