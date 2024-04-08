use std::{fs::File, io, path::Path};

use rcgen::{
	BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
	DnValue::PrintableString, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};

#[cfg(feature = "aws_lc_rs")]
use aws_lc_rs as ring_like;
#[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
use ring as ring_like;

#[derive(Debug, Clone)]
/// PEM serialized Certificate and PEM serialized corresponding private key
pub struct PemCertifiedKey {
	pub cert_pem: String,
	pub private_key_pem: String,
}

impl PemCertifiedKey {
	pub fn write(&self, dir: &Path, name: &str) -> Result<(), io::Error> {
		use std::io::Write;
		std::fs::create_dir_all(dir)?;

		let key_path = dir.join(format!("{name}.key.pem"));
		let mut key_out = File::create(key_path)?;
		write!(key_out, "{}", &self.private_key_pem)?;

		let cert_path = dir.join(format!("{name}.pem"));
		let mut cert_out = File::create(cert_path)?;
		write!(cert_out, "{}", &self.cert_pem)?;

		Ok(())
	}
}

/// Builder to configure TLS [CertificateParams] to be finalized
/// into either a [Ca] or an [EndEntity].
#[derive(Default)]
pub struct CertificateBuilder {
	params: CertificateParams,
	alg: KeyPairAlgorithm,
}

impl CertificateBuilder {
	/// Initialize `CertificateParams` with defaults
	/// # Example
	/// ```
	/// # use rustls_cert_gen::CertificateBuilder;
	/// let cert = CertificateBuilder::new();
	/// ```
	pub fn new() -> Self {
		let mut params = CertificateParams::default();
		// override default Common Name
		params.distinguished_name = DistinguishedName::new();
		Self {
			params,
			alg: KeyPairAlgorithm::EcdsaP256,
		}
	}
	/// Set signature algorithm (instead of default).
	pub fn signature_algorithm(mut self, alg: KeyPairAlgorithm) -> anyhow::Result<Self> {
		self.alg = alg;
		Ok(self)
	}
	/// Set options for Ca Certificates
	/// # Example
	/// ```
	/// # use rustls_cert_gen::CertificateBuilder;
	/// let cert = CertificateBuilder::new().certificate_authority();
	/// ```
	pub fn certificate_authority(self) -> CaBuilder {
		CaBuilder::new(self.params, self.alg)
	}
	/// Set options for `EndEntity` Certificates
	pub fn end_entity(self) -> EndEntityBuilder {
		EndEntityBuilder::new(self.params, self.alg)
	}
}

/// [CertificateParams] from which an [Ca] [Certificate] can be built
pub struct CaBuilder {
	params: CertificateParams,
	alg: KeyPairAlgorithm,
}

impl CaBuilder {
	/// Initialize `CaBuilder`
	pub fn new(mut params: CertificateParams, alg: KeyPairAlgorithm) -> Self {
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		params.key_usages.push(KeyUsagePurpose::KeyCertSign);
		params.key_usages.push(KeyUsagePurpose::CrlSign);
		Self { params, alg }
	}
	/// Add CountryName to `distinguished_name`. Multiple calls will
	/// replace previous value.
	pub fn country_name(mut self, country: &str) -> Result<Self, rcgen::Error> {
		self.params
			.distinguished_name
			.push(DnType::CountryName, PrintableString(country.try_into()?));
		Ok(self)
	}
	/// Add OrganizationName to `distinguished_name`. Multiple calls will
	/// replace previous value.
	pub fn organization_name(mut self, name: &str) -> Self {
		self.params
			.distinguished_name
			.push(DnType::OrganizationName, name);
		self
	}
	/// build `Ca` Certificate.
	pub fn build(self) -> Result<Ca, rcgen::Error> {
		let key_pair = self.alg.to_key_pair()?;
		let cert = self.params.self_signed(&key_pair)?;
		Ok(Ca { cert, key_pair })
	}
}

/// End-entity [Certificate]
pub struct Ca {
	cert: Certificate,
	key_pair: KeyPair,
}

impl Ca {
	/// Self-sign and serialize
	pub fn serialize_pem(&self) -> PemCertifiedKey {
		PemCertifiedKey {
			cert_pem: self.cert.pem(),
			private_key_pem: self.key_pair.serialize_pem(),
		}
	}
	/// Return `&Certificate`
	#[allow(dead_code)]
	pub fn cert(&self) -> &Certificate {
		&self.cert
	}
}

/// End-entity [Certificate]
pub struct EndEntity {
	cert: Certificate,
	key_pair: KeyPair,
}

impl EndEntity {
	/// Sign with `signer` and serialize.
	pub fn serialize_pem(&self) -> PemCertifiedKey {
		PemCertifiedKey {
			cert_pem: self.cert.pem(),
			private_key_pem: self.key_pair.serialize_pem(),
		}
	}
}

/// [CertificateParams] from which an [EndEntity] [Certificate] can be built
pub struct EndEntityBuilder {
	params: CertificateParams,
	alg: KeyPairAlgorithm,
}

impl EndEntityBuilder {
	/// Initialize `EndEntityBuilder`
	pub fn new(mut params: CertificateParams, alg: KeyPairAlgorithm) -> Self {
		params.is_ca = IsCa::NoCa;
		params.use_authority_key_identifier_extension = true;
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		Self { params, alg }
	}
	/// Add CommonName to `distinguished_name`. Multiple calls will
	/// replace previous value.
	pub fn common_name(mut self, name: &str) -> Self {
		self.params
			.distinguished_name
			.push(DnType::CommonName, name);
		self
	}
	/// `SanTypes` that will be recorded as
	/// `subject_alt_names`. Multiple calls will append to previous
	/// values.
	pub fn subject_alternative_names(mut self, sans: Vec<SanType>) -> Self {
		self.params.subject_alt_names.extend(sans);
		self
	}
	/// Add ClientAuth to `extended_key_usages` if it is not already present.
	pub fn client_auth(&mut self) -> &Self {
		let usage = ExtendedKeyUsagePurpose::ClientAuth;
		if !self.params.extended_key_usages.iter().any(|e| e == &usage) {
			self.params.extended_key_usages.push(usage);
		}
		self
	}
	/// Add ServerAuth to `extended_key_usages` if it is not already present.
	pub fn server_auth(&mut self) -> &Self {
		let usage = ExtendedKeyUsagePurpose::ServerAuth;
		if !self.params.extended_key_usages.iter().any(|e| e == &usage) {
			self.params.extended_key_usages.push(usage);
		}
		self
	}
	/// build `EndEntity` Certificate.
	pub fn build(self, issuer: &Ca) -> Result<EndEntity, rcgen::Error> {
		let key_pair = self.alg.to_key_pair()?;
		let cert = self
			.params
			.signed_by(&key_pair, &issuer.cert, &issuer.key_pair)?;
		Ok(EndEntity { cert, key_pair })
	}
}

/// Supported Keypair Algorithms
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum KeyPairAlgorithm {
	/// RSA
	///
	/// See [`PKCS_RSA_SHA256`](rcgen::PKCS_RSA_SHA256).
	Rsa,
	/// Ed25519
	///
	/// See [`PKCS_ED25519`](rcgen::PKCS_ED25519).
	Ed25519,
	/// ECDSA with the P-256 curve
	///
	/// See [`PKCS_ECDSA_P256_SHA256`](rcgen::PKCS_ECDSA_P256_SHA256).
	#[default]
	EcdsaP256,
	/// ECDSA with the P-384 curve
	///
	/// See [`PKCS_ECDSA_P384_SHA256`](rcgen::PKCS_ECDSA_P384_SHA384).
	EcdsaP384,
	/// ECDSA with the P-521 curve
	///
	/// See [`PKCS_ECDSA_P521_SHA256`](rcgen::PKCS_ECDSA_P521_SHA512).
	#[cfg(feature = "aws_lc_rs")]
	EcdsaP521,
}

impl KeyPairAlgorithm {
	/// Return an `rcgen::KeyPair` for the given varient
	fn to_key_pair(self) -> Result<rcgen::KeyPair, rcgen::Error> {
		match self {
			KeyPairAlgorithm::Rsa => rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256),
			KeyPairAlgorithm::Ed25519 => {
				use ring_like::signature::Ed25519KeyPair;

				let rng = ring_like::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ED25519;
				let pkcs8_bytes =
					Ed25519KeyPair::generate_pkcs8(&rng).or(Err(rcgen::Error::RingUnspecified))?;

				rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_bytes.as_ref().into(), alg)
			},
			KeyPairAlgorithm::EcdsaP256 => {
				use ring_like::signature::EcdsaKeyPair;
				use ring_like::signature::ECDSA_P256_SHA256_ASN1_SIGNING;

				let rng = ring_like::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
				let pkcs8_bytes =
					EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
						.or(Err(rcgen::Error::RingUnspecified))?;
				rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_bytes.as_ref().into(), alg)
			},
			KeyPairAlgorithm::EcdsaP384 => {
				use ring_like::signature::EcdsaKeyPair;
				use ring_like::signature::ECDSA_P384_SHA384_ASN1_SIGNING;

				let rng = ring_like::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
				let pkcs8_bytes =
					EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
						.or(Err(rcgen::Error::RingUnspecified))?;

				rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_bytes.as_ref().into(), alg)
			},
			#[cfg(feature = "aws_lc_rs")]
			KeyPairAlgorithm::EcdsaP521 => {
				use ring_like::signature::EcdsaKeyPair;
				use ring_like::signature::ECDSA_P521_SHA512_ASN1_SIGNING;

				let rng = ring_like::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ECDSA_P521_SHA512;
				let pkcs8_bytes =
					EcdsaKeyPair::generate_pkcs8(&ECDSA_P521_SHA512_ASN1_SIGNING, &rng)
						.or(Err(rcgen::Error::RingUnspecified))?;

				rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_bytes.as_ref().into(), alg)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use x509_parser::prelude::{FromDer, X509Certificate};

	use super::*;

	#[test]
	fn test_write_files() -> anyhow::Result<()> {
		use assert_fs::prelude::*;
		let temp = assert_fs::TempDir::new()?;
		let dir = temp.path();
		let entity_cert = temp.child("cert.pem");
		let entity_key = temp.child("cert.key.pem");

		let pck = PemCertifiedKey {
			cert_pem: "x".into(),
			private_key_pem: "y".into(),
		};

		pck.write(dir, "cert")?;

		// assert contents of created files
		entity_cert.assert("x");
		entity_key.assert("y");

		Ok(())
	}
	#[test]
	fn init_ca() {
		let cert = CertificateBuilder::new().certificate_authority();
		assert_eq!(cert.params.is_ca, IsCa::Ca(BasicConstraints::Unconstrained))
	}
	#[test]
	fn with_sig_algo_default() -> anyhow::Result<()> {
		let end_entity = CertificateBuilder::new().end_entity();

		assert_eq!(end_entity.alg, KeyPairAlgorithm::EcdsaP256);
		Ok(())
	}
	#[test]
	fn serialize_end_entity_default_sig() -> anyhow::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.end_entity()
			.build(&ca)?
			.serialize_pem();

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem().cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		assert!(!cert.is_ca());
		check_signature(&cert, &issuer);

		Ok(())
	}
	#[test]
	fn serialize_end_entity_ecdsa_p384_sha384_sig() -> anyhow::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.signature_algorithm(KeyPairAlgorithm::EcdsaP384)?
			.end_entity()
			.build(&ca)?
			.serialize_pem();

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem().cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		check_signature(&cert, &issuer);
		Ok(())
	}

	#[test]
	#[cfg(feature = "aws_lc_rs")]
	fn serialize_end_entity_ecdsa_p521_sha512_sig() -> anyhow::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.signature_algorithm(KeyPairAlgorithm::EcdsaP521)?
			.end_entity()
			.build(&ca)?
			.serialize_pem();

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem().cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		check_signature(&cert, &issuer);
		Ok(())
	}

	#[test]
	fn serialize_end_entity_ed25519_sig() -> anyhow::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.signature_algorithm(KeyPairAlgorithm::Ed25519)?
			.end_entity()
			.build(&ca)?
			.serialize_pem();

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem().cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		check_signature(&cert, &issuer);
		Ok(())
	}
	pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) {
		let verified = cert.verify_signature(Some(issuer.public_key())).is_ok();
		assert!(verified);
	}

	#[test]
	fn init_end_endity() {
		let params = CertificateParams::default();
		let cert = EndEntityBuilder::new(params, KeyPairAlgorithm::default());
		assert_eq!(cert.params.is_ca, IsCa::NoCa)
	}
	#[test]
	fn client_auth_end_entity() {
		let _ca = CertificateBuilder::new()
			.certificate_authority()
			.build()
			.unwrap();
		let params = CertificateParams::default();
		let mut cert = EndEntityBuilder::new(params, KeyPairAlgorithm::default());
		assert_eq!(cert.params.is_ca, IsCa::NoCa);
		assert_eq!(
			cert.client_auth().params.extended_key_usages,
			vec![ExtendedKeyUsagePurpose::ClientAuth]
		);
	}
	#[test]
	fn server_auth_end_entity() {
		let _ca = CertificateBuilder::new()
			.certificate_authority()
			.build()
			.unwrap();
		let params = CertificateParams::default();
		let mut cert = EndEntityBuilder::new(params, KeyPairAlgorithm::default());
		assert_eq!(cert.params.is_ca, IsCa::NoCa);
		assert_eq!(
			cert.server_auth().params.extended_key_usages,
			vec![ExtendedKeyUsagePurpose::ServerAuth]
		);
	}
	#[test]
	fn sans_end_entity() {
		let _ca = CertificateBuilder::new()
			.certificate_authority()
			.build()
			.unwrap();
		let name = "unexpected.oomyoo.xyz";
		let names = vec![SanType::DnsName(name.try_into().unwrap())];
		let params = CertificateParams::default();
		let cert = EndEntityBuilder::new(params, KeyPairAlgorithm::default())
			.subject_alternative_names(names);
		assert_eq!(
			cert.params.subject_alt_names,
			vec![rcgen::SanType::DnsName(name.try_into().unwrap())]
		);
	}
	#[test]
	fn sans_end_entity_empty() {
		let _ca = CertificateBuilder::new()
			.certificate_authority()
			.build()
			.unwrap();
		let names = vec![];
		let params = CertificateParams::default();
		let cert = EndEntityBuilder::new(params, KeyPairAlgorithm::default())
			.subject_alternative_names(names);
		assert_eq!(cert.params.subject_alt_names, vec![]);
	}

	#[test]
	fn key_pair_algorithm_to_keypair() -> anyhow::Result<()> {
		let keypair = KeyPairAlgorithm::Ed25519.to_key_pair()?;
		assert_eq!(format!("{:?}", keypair.algorithm()), "PKCS_ED25519");
		let keypair = KeyPairAlgorithm::EcdsaP256.to_key_pair()?;
		assert_eq!(
			format!("{:?}", keypair.algorithm()),
			"PKCS_ECDSA_P256_SHA256"
		);
		let keypair = KeyPairAlgorithm::EcdsaP384.to_key_pair()?;
		assert_eq!(
			format!("{:?}", keypair.algorithm()),
			"PKCS_ECDSA_P384_SHA384"
		);

		#[cfg(feature = "aws_lc_rs")]
		{
			let keypair = KeyPairAlgorithm::EcdsaP521.to_key_pair()?;
			assert_eq!(
				format!("{:?}", keypair.algorithm()),
				"PKCS_ECDSA_P521_SHA512"
			);
		}
		Ok(())
	}
}
