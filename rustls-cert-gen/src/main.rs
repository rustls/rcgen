use bpaf::Bpaf;
use rcgen::SanType;
use std::net::IpAddr;
use std::path::PathBuf;

mod cert;
use cert::CertificateBuilder;
#[cfg(feature = "crypto")]
use cert::{keypair_algorithm, KeypairAlgorithm};

fn main() -> anyhow::Result<()> {
	let opts = options().run();

	let ca = CertificateBuilder::new();
	#[cfg(feature = "crypto")]
	let ca = ca.signature_algorithm(&opts.keypair_algorithm)?;
	let ca = ca
		.certificate_authority()
		.country_name(&opts.country_name)
		.organization_name(&opts.organization_name)
		.build()?;

	let entity = CertificateBuilder::new();
	#[cfg(feature = "crypto")]
	let entity = entity.signature_algorithm(&opts.keypair_algorithm)?;
	let mut entity = entity
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
		.build()?
		.serialize_pem(ca.cert())?
		.write(&opts.output, &opts.cert_file_name)?;

	ca.serialize_pem()?
		.write(&opts.output, &opts.ca_file_name)?;

	Ok(())
}
/// #[cfg(feature = "crypto")]
#[derive(Clone, Debug, Bpaf)]
#[bpaf(options)]
/// rustls-cert-gen TLS Certificate Generator
struct Options {
	/// Output directory for generated files
	#[bpaf(short, long, argument("output/path/"))]
	pub output: PathBuf,
	/// Keypair algorithm
	#[cfg(feature = "crypto")]
	#[bpaf(
		external(keypair_algorithm),
		fallback(KeypairAlgorithm::EcdsaP256),
		display_fallback,
		group_help("Keypair Algorithm:")
	)]
	#[cfg(feature = "crypto")]
	pub keypair_algorithm: KeypairAlgorithm,
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
	#[bpaf(many, long, argument::<String>("san"), map(parse_sans))]
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
fn parse_sans(hosts: Vec<String>) -> Vec<SanType> {
	hosts
		.into_iter()
		.map(|host| {
			if let Ok(ip) = host.parse::<IpAddr>() {
				SanType::IpAddress(ip)
			} else {
				SanType::DnsName(host)
			}
		})
		.collect()
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
		let sans: Vec<SanType> = parse_sans(hosts);
		assert_eq!(SanType::DnsName("my.host.com".into()), sans[0]);
		assert_eq!(SanType::DnsName("localhost".into()), sans[1]);
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
