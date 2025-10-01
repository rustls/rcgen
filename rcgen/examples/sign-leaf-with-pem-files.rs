//! Generate a new certificate, and sign it with an existing root or
//! intermediate certificate.
//!
//! Requires four positional command line arguments:
//! * File path to PEM containing signer's key pair
//! * File path to PEM containing signer's certificate
//! * File path for generated PEM containing output key pair
//! * File path for generated PEM containing output certificate

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn Error>> {
	let mut args = std::env::args().skip(1);

	let signer_keys_file = PathBuf::from(
		args.next()
			.ok_or("provide signer's pem keys file as 1st argument")?,
	);

	let signer_cert_file = PathBuf::from(
		args.next()
			.ok_or("provide signer's pem certificate file as 2nd argument")?,
	);

	let output_keys_file =
		PathBuf::from(args.next().ok_or("output pem keys file as 3rd argument")?);

	let output_cert_file = PathBuf::from(args.next().ok_or("output pem cert file as 4th fourth")?);

	// Read existing certificate authority
	let keys_pem = fs::read_to_string(&signer_keys_file)?;
	let cert_pem = fs::read_to_string(&signer_cert_file)?;

	let key_pair = KeyPair::from_pem(&keys_pem)?;
	let signer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;

	// Create a new signed server certificate
	const DOMAIN: &str = "example.domain";

	let sans = vec![DOMAIN.into()];

	let mut params = CertificateParams::new(sans)?;

	params.distinguished_name.push(DnType::CommonName, DOMAIN);
	params.use_authority_key_identifier_extension = true;
	params.key_usages.push(KeyUsagePurpose::DigitalSignature);
	params
		.extended_key_usages
		.push(ExtendedKeyUsagePurpose::ServerAuth);

	const DAY: Duration = Duration::days(1);

	let yesterday = OffsetDateTime::now_utc()
		.checked_sub(DAY)
		.ok_or("invalid yesterday")?;

	let tomorrow = OffsetDateTime::now_utc()
		.checked_add(DAY)
		.ok_or("invalid tomorrow")?;

	params.not_before = yesterday;
	params.not_after = tomorrow;

	let output_keys = KeyPair::generate()?;
	let output_cert = params.signed_by(&output_keys, &signer)?;

	// Write new certificate
	fs::write(&output_keys_file, output_keys.serialize_pem())?;
	fs::write(&output_cert_file, output_cert.pem())?;

	println!("Wrote signed leaf certificate:");
	println!("  keys: {}", output_keys_file.display());
	println!("  cert: {}", output_cert_file.display());
	println!();

	Ok(())
}
