//! Command Line argument parsing
#![allow(missing_docs)]

use std::{net::IpAddr, path::PathBuf};

use bpaf::Bpaf;
use rcgen::SanType;

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options)]
/// rustls-cert-gen Tls Certificate Generator
pub struct Options {
	/// Output Directory for generated files
	#[bpaf(short, long, argument("output/path/"))]
	pub output: PathBuf,
	/// Signature algorithm
	#[bpaf(short, long, fallback("ecdsa_p256".into()), display_fallback)]
	pub sig_algo: String,
	#[bpaf(external)]
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
	hosts.into_iter().map(parse_san).collect()
}

fn parse_san(host: String) -> SanType {
	if let Ok(ip) = host.parse::<IpAddr>() {
		SanType::IpAddress(ip)
	} else {
		SanType::DnsName(host)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_san() {
		let hosts = vec!["my.host.com", "localhost", "185.199.108.153"];
		let sans: Vec<SanType> = hosts.into_iter().map(Into::into).map(parse_san).collect();
		assert_eq!(SanType::DnsName("my.host.com".into()), sans[0]);
		assert_eq!(SanType::DnsName("localhost".into()), sans[1]);
		assert_eq!(
			SanType::IpAddress("185.199.108.153".parse().unwrap()),
			sans[2]
		);
	}
}
