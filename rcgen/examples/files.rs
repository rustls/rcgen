use rcgen::{
	BasicConstraints, Certificate, CertificateParams, DnType, DnValue::PrintableString,
	ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

/// Generate a certificate chain, saving each step to filesystem and loading from filesystem for next step.
fn main() {
	let output_dir = std::env::args()
		.nth(1)
		.map(PathBuf::from)
		.expect("provide output directory as first command line argument");

	if !output_dir.exists() {
		panic!("output directory {} does not exist", output_dir.display());
	}

	let ca_keys_file = output_dir.join("ca-keys.pem");
	let ca_cert_file = output_dir.join("ca-cert.pem");

	let intermediate_keys_file = output_dir.join("intermediate-keys.pem");
	let intermediate_cert_file = output_dir.join("intermediate-cert.pem");

	let server_keys_file = output_dir.join("server-keys.pem");
	let server_cert_file = output_dir.join("server-cert.pem");

	write_new_ca(&ca_keys_file, &ca_cert_file);

	write_new_intermediate_ca(
		&ca_keys_file,
		&ca_cert_file,
		&intermediate_keys_file,
		&intermediate_cert_file,
	);

	write_new_server(
		&intermediate_keys_file,
		&intermediate_cert_file,
		&server_keys_file,
		&server_cert_file,
	);

	println!(
		"Wrote root ca, intermediate ca, and leaf certificate to {}",
		output_dir.display()
	);
	println!();

	#[cfg(unix)]
	{
		let verify_command = format!(
			"openssl verify -CAfile <(cat \"{}\" \"{}\") \"{}\"",
			ca_cert_file.display(),
			intermediate_cert_file.display(),
			server_cert_file.display()
		);

		println!("To verify the certificate chain, run:");
		println!();
		println!("  {verify_command}");
		println!();
	}
}

fn read_ca(keys_file: &Path, cert_file: &Path) -> Issuer<'static, KeyPair> {
	let keys_pem = std::fs::read_to_string(keys_file).expect("failed to read keys file");
	let cert_pem = std::fs::read_to_string(cert_file).expect("failed to read cert file");

	let key_pair = KeyPair::from_pem(&keys_pem).expect("failed to parse keys file");

	Issuer::from_ca_cert_pem(&cert_pem, key_pair).expect("failed to parse cert")
}

fn write_cert(key_file: &Path, cert_file: &Path, key_pair: KeyPair, cert: Certificate) {
	std::fs::write(key_file, key_pair.serialize_pem()).expect("failed to write keys file");
	std::fs::write(cert_file, cert.pem()).expect("failed to write cert file");
}

fn write_new_ca(key_file: &Path, cert_file: &Path) {
	let (key_pair, params) = new_unsigned_ca();

	let cert = params.self_signed(&key_pair).unwrap();

	write_cert(key_file, cert_file, key_pair, cert);
}

fn new_unsigned_ca() -> (KeyPair, CertificateParams) {
	const NAME: &str = "Example Root CA";

	let mut params = CertificateParams::new([]).unwrap();

	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

	params.distinguished_name.push(
		DnType::CountryName,
		PrintableString("BR".try_into().unwrap()),
	);
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, NAME);

	params.key_usages.push(KeyUsagePurpose::DigitalSignature);
	params.key_usages.push(KeyUsagePurpose::KeyCertSign);
	params.key_usages.push(KeyUsagePurpose::CrlSign);

	let (yesterday, tomorrow) = validity_period();

	params.not_before = yesterday;
	params.not_after = tomorrow;

	let key_pair = KeyPair::generate().unwrap();

	(key_pair, params)
}

fn write_new_intermediate_ca(
	ca_key_file: &Path,
	ca_cert_file: &Path,
	intermediate_keys_file: &Path,
	intermediate_cert_file: &Path,
) {
	let ca_issuer = read_ca(ca_key_file, ca_cert_file);

	let (key_pair, params) = new_unsigned_intermediate_ca();
	let cert = params.signed_by(&key_pair, &ca_issuer).unwrap();

	let keys_pem = key_pair.serialize_pem();
	let cert_pem = cert.pem();

	std::fs::write(intermediate_keys_file, keys_pem)
		.expect("failed to write intermediate keys file");

	std::fs::write(intermediate_cert_file, cert_pem)
		.expect("failed to write intermediate cert file");
}

fn new_unsigned_intermediate_ca() -> (KeyPair, CertificateParams) {
	const NAME: &str = "Example Intermediate CA";

	let mut params = CertificateParams::new([]).unwrap();

	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

	params.distinguished_name.push(
		DnType::CountryName,
		PrintableString("BR".try_into().unwrap()),
	);
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, NAME);

	params.key_usages.push(KeyUsagePurpose::DigitalSignature);
	params.key_usages.push(KeyUsagePurpose::KeyCertSign);
	params.key_usages.push(KeyUsagePurpose::CrlSign);

	let (yesterday, tomorrow) = validity_period();

	params.not_before = yesterday;
	params.not_after = tomorrow;

	let key_pair = KeyPair::generate().unwrap();

	(key_pair, params)
}

fn write_new_server(
	intermediate_keys_file: &Path,
	intermediate_cert_file: &Path,
	keys_file: &Path,
	cert_file: &Path,
) {
	let intermediate_issuer = read_ca(intermediate_keys_file, intermediate_cert_file);

	let (key_pair, cert) = new_signed_server(&intermediate_issuer);

	let keys_pem = key_pair.serialize_pem();
	let cert_pem = cert.pem();

	std::fs::write(keys_file, keys_pem).expect("failed to write server keys file");
	std::fs::write(cert_file, cert_pem).expect("failed to write server cert file");
}

fn new_signed_server(issuer: &Issuer<'static, KeyPair>) -> (KeyPair, Certificate) {
	const DOMAIN: &str = "example.domain";

	let sans = vec![DOMAIN.into()];

	let mut params = CertificateParams::new(sans).expect("invalid subject alt name");

	params.distinguished_name.push(DnType::CommonName, DOMAIN);
	params.use_authority_key_identifier_extension = true;
	params.key_usages.push(KeyUsagePurpose::DigitalSignature);
	params
		.extended_key_usages
		.push(ExtendedKeyUsagePurpose::ServerAuth);

	let (yesterday, tomorrow) = validity_period();

	params.not_before = yesterday;
	params.not_after = tomorrow;

	let key_pair = KeyPair::generate().unwrap();
	let cert = params.signed_by(&key_pair, issuer).unwrap();

	(key_pair, cert)
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
	const DAY: Duration = Duration::days(1);

	let yesterday = OffsetDateTime::now_utc().checked_sub(DAY).unwrap();
	let tomorrow = OffsetDateTime::now_utc().checked_add(DAY).unwrap();

	(yesterday, tomorrow)
}
