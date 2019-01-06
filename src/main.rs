extern crate rcgen;
extern crate chrono;

use chrono::{NaiveDate, DateTime, Utc};
use rcgen::{Certificate, CertificateParams,
	DistinguishedName, DnType,
	PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION};
use std::fs;
use std::io::Result;

fn main() -> Result<()> {
	let not_before = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2000, 01, 01).and_hms_milli(0, 0, 0, 0), Utc);
	let not_after = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2020, 01, 01).and_hms_milli(0, 0, 0, 0), Utc);
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
	println!("{}", cert.serialize_private_key_pem());
	std::fs::create_dir_all("certs/")?;
	fs::write("certs/cert.pem", &cert.serialize_pem().as_bytes())?;
	fs::write("certs/cert.der", &cert.serialize_der())?;
	fs::write("certs/key.pem", &cert.serialize_private_key_pem().as_bytes())?;
	fs::write("certs/key.der", &cert.serialize_private_key_der())?;
	Ok(())
}
