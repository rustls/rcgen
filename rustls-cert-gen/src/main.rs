use std::{fmt, net::IpAddr, path::PathBuf, str::FromStr};

use bpaf::Bpaf;
use rcgen::{Error, SanType};

use rustls_cert_gen::CertificateBuilder;

fn main() -> anyhow::Result<()> {
	let opts = options().run();

	let ca = CertificateBuilder::new()
		.signature_algorithm(opts.keypair_algorithm.into())?
		.certificate_authority()
		.country_name(&opts.country_name)?
		.organization_name(&opts.organization_name)
		.build()?;

	let mut entity = CertificateBuilder::new()
		.signature_algorithm(opts.keypair_algorithm.into())?
		.end_entity()
		.common_name(&opts.common_name)
		.subject_alternative_names(opts.san);

	if opts.client_auth {
		entity.client_auth();
	};

	if opts.server_auth {
		entity.server_auth();
	};

	entity
		.build(&ca)?
		.serialize_pem()
		.write(&opts.output, &opts.cert_file_name)?;

	ca.serialize_pem().write(&opts.output, &opts.ca_file_name)?;

	Ok(())
}

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options)]
/// rustls-cert-gen TLS Certificate Generator
struct Options {
	/// Output directory for generated files
	#[bpaf(short, long, argument("output/path/"))]
	pub output: PathBuf,
	/// Keypair algorithm
	#[bpaf(
		external(key_pair_algorithm),
		fallback(KeyPairAlgorithm::EcdsaP256),
		display_fallback,
		group_help("Keypair Algorithm:")
	)]
	pub keypair_algorithm: KeyPairAlgorithm,
	/// Extended Key Usage Purpose: ClientAuth
	#[bpaf(long)]
	pub client_auth: bool,
	/// Extended Key Usage Purpose: ServerAuth
	#[bpaf(long)]
	pub server_auth: bool,
	/// Basename for end-entity cert/key
	#[bpaf(long, fallback("cert".into()), display_fallback)]
	pub cert_file_name: String,
	/// Basename for ca cert/key
	#[bpaf(long, fallback("root-ca".into()), display_fallback)]
	pub ca_file_name: String,
	/// Subject Alt Name (apply multiple times for multiple names/Ips)
	#[bpaf(many, long, argument::<String>("san"), parse(parse_sans))]
	pub san: Vec<SanType>,
	/// Common Name (Currently only used for end-entity)
	#[bpaf(long, fallback("Tls End-Entity Certificate".into()), display_fallback)]
	pub common_name: String,
	/// Country Name (Currently only used for ca)
	#[bpaf(long, fallback("BR".into()), display_fallback)]
	pub country_name: String,
	/// Organization Name (Currently only used for ca)
	#[bpaf(long, fallback("Crab widgits SE".into()), display_fallback)]
	pub organization_name: String,
}

/// Parse cli input into SanType. Try first `IpAddr`, if that fails
/// declare it to be a DnsName.
fn parse_sans(hosts: Vec<String>) -> Result<Vec<SanType>, Error> {
	hosts
		.into_iter()
		.map(|s| {
			Ok(match IpAddr::from_str(&s) {
				Ok(ip) => SanType::IpAddress(ip),
				Err(_) => SanType::DnsName(s.try_into()?),
			})
		})
		.collect()
}

/// Supported Keypair Algorithms
#[derive(Clone, Copy, Debug, Default, Bpaf, PartialEq)]
pub enum KeyPairAlgorithm {
	Rsa,
	Ed25519,
	#[default]
	EcdsaP256,
	EcdsaP384,
	#[cfg(feature = "aws_lc_rs")]
	EcdsaP521,
}

impl From<KeyPairAlgorithm> for rustls_cert_gen::KeyPairAlgorithm {
	fn from(value: KeyPairAlgorithm) -> Self {
		match value {
			KeyPairAlgorithm::Rsa => rustls_cert_gen::KeyPairAlgorithm::Rsa,
			KeyPairAlgorithm::Ed25519 => rustls_cert_gen::KeyPairAlgorithm::Ed25519,
			KeyPairAlgorithm::EcdsaP256 => rustls_cert_gen::KeyPairAlgorithm::EcdsaP256,
			KeyPairAlgorithm::EcdsaP384 => rustls_cert_gen::KeyPairAlgorithm::EcdsaP384,
			#[cfg(feature = "aws_lc_rs")]
			KeyPairAlgorithm::EcdsaP521 => rustls_cert_gen::KeyPairAlgorithm::EcdsaP521,
		}
	}
}

impl From<rustls_cert_gen::KeyPairAlgorithm> for KeyPairAlgorithm {
	fn from(value: rustls_cert_gen::KeyPairAlgorithm) -> Self {
		match value {
			rustls_cert_gen::KeyPairAlgorithm::Rsa => KeyPairAlgorithm::Rsa,
			rustls_cert_gen::KeyPairAlgorithm::Ed25519 => KeyPairAlgorithm::Ed25519,
			rustls_cert_gen::KeyPairAlgorithm::EcdsaP256 => KeyPairAlgorithm::EcdsaP256,
			rustls_cert_gen::KeyPairAlgorithm::EcdsaP384 => KeyPairAlgorithm::EcdsaP384,
			#[cfg(feature = "aws_lc_rs")]
			rustls_cert_gen::KeyPairAlgorithm::EcdsaP521 => KeyPairAlgorithm::EcdsaP521,
		}
	}
}

impl fmt::Display for KeyPairAlgorithm {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			KeyPairAlgorithm::Rsa => write!(f, "rsa"),
			KeyPairAlgorithm::Ed25519 => write!(f, "ed25519"),
			KeyPairAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
			KeyPairAlgorithm::EcdsaP384 => write!(f, "ecdsa-p384"),
			#[cfg(feature = "aws_lc_rs")]
			KeyPairAlgorithm::EcdsaP521 => write!(f, "ecdsa-p521"),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_san() {
		let hosts = vec![
			"my.host.com",
			"localhost",
			"185.199.108.153",
			"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		]
		.into_iter()
		.map(Into::into)
		.collect();
		let sans: Vec<SanType> = parse_sans(hosts).unwrap();
		assert_eq!(SanType::DnsName("my.host.com".try_into().unwrap()), sans[0]);
		assert_eq!(SanType::DnsName("localhost".try_into().unwrap()), sans[1]);
		assert_eq!(
			SanType::IpAddress("185.199.108.153".parse().unwrap()),
			sans[2]
		);
		assert_eq!(
			SanType::IpAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap()),
			sans[3]
		);
	}
}
