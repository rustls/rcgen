use rcgen::{
	date_time_ymd, Certificate, CertificateParams, CertifiedKey, DistinguishedName, DnType, SanType,
};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut params: CertificateParams = Default::default();
	params.not_before = date_time_ymd(1975, 1, 1);
	params.not_after = date_time_ymd(4096, 1, 1);
	params.distinguished_name = DistinguishedName::new();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Master Cert");
	params.subject_alt_names = vec![
		SanType::DnsName("crabs.crabs".to_string()),
		SanType::DnsName("localhost".to_string()),
	];

	let CertifiedKey { cert, key_pair } = Certificate::generate_self_signed(params)?;

	let pem_serialized = cert.pem();
	let pem = pem::parse(&pem_serialized)?;
	let der_serialized = pem.contents();
	println!("{pem_serialized}");
	println!("{}", key_pair.serialize_pem());
	fs::create_dir_all("certs/")?;
	fs::write("certs/cert.pem", pem_serialized.as_bytes())?;
	fs::write("certs/cert.der", der_serialized)?;
	fs::write("certs/key.pem", key_pair.serialize_pem().as_bytes())?;
	fs::write("certs/key.der", key_pair.serialize_der())?;
	Ok(())
}
