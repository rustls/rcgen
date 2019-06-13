extern crate rcgen;

use rcgen::{Certificate, CertificateParams,
	DistinguishedName, DnType,
	date_time_ymd};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut params :CertificateParams =  Default::default();
	params.not_before = date_time_ymd(1975, 01, 01);
	params.not_after = date_time_ymd(4096, 01, 01);
	params.distinguished_name = DistinguishedName::new();
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master Cert");
	params.subject_alt_names = vec!["crabs.crabs".to_string(), "localhost".to_string()];

	let cert = Certificate::from_params(params)?;
	println!("{}", cert.serialize_pem().unwrap());
	println!("{}", cert.serialize_private_key_pem());
	std::fs::create_dir_all("certs/")?;
	fs::write("certs/cert.pem", &cert.serialize_pem().unwrap().as_bytes())?;
	fs::write("certs/cert.der", &cert.serialize_der().unwrap())?;
	fs::write("certs/key.pem", &cert.serialize_private_key_pem().as_bytes())?;
	fs::write("certs/key.der", &cert.serialize_private_key_der())?;
	Ok(())
}
