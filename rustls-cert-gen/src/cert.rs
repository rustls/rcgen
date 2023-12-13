use bpaf::Bpaf;
use rcgen::{
	BasicConstraints, Certificate, CertificateParams, CertifiedKey, DistinguishedName, DnType,
	DnValue::PrintableString, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::{fmt, fs::File, io, path::Path};

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
		Self { params }
	}
	/// Set signature algorithm (instead of default).
	pub fn signature_algorithm(mut self, alg: &KeypairAlgorithm) -> anyhow::Result<Self> {
		let keypair = alg.to_keypair()?;
		self.params.alg = keypair.algorithm();
		self.params.key_pair = Some(keypair);
		Ok(self)
	}
	/// Set options for Ca Certificates
	/// # Example
	/// ```
	/// # use rustls_cert_gen::CertificateBuilder;
	/// let cert = CertificateBuilder::new().certificate_authority();
	/// ```
	pub fn certificate_authority(self) -> CaBuilder {
		CaBuilder::new(self.params)
	}
	/// Set options for `EndEntity` Certificates
	pub fn end_entity(self) -> EndEntityBuilder {
		EndEntityBuilder::new(self.params)
	}
}

/// [CertificateParams] from which an [Ca] [Certificate] can be built
pub struct CaBuilder {
	params: CertificateParams,
}

impl CaBuilder {
	/// Initialize `CaBuilder`
	pub fn new(mut params: CertificateParams) -> Self {
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		params.key_usages.push(KeyUsagePurpose::KeyCertSign);
		params.key_usages.push(KeyUsagePurpose::CrlSign);
		Self { params }
	}
	/// Add CountryName to `distinguished_name`. Multiple calls will
	/// replace previous value.
	pub fn country_name(mut self, country: &str) -> Self {
		self.params
			.distinguished_name
			.push(DnType::CountryName, PrintableString(country.into()));
		self
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
		let CertifiedKey { cert, key_pair } = Certificate::generate_self_signed(self.params)?;
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
}

impl EndEntityBuilder {
	/// Initialize `EndEntityBuilder`
	pub fn new(mut params: CertificateParams) -> Self {
		params.is_ca = IsCa::NoCa;
		params.use_authority_key_identifier_extension = true;
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		Self { params }
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
		let CertifiedKey { cert, key_pair } =
			Certificate::generate(self.params, &issuer.cert, &issuer.key_pair)?;
		Ok(EndEntity { cert, key_pair })
	}
}

#[derive(Clone, Debug, Bpaf)]
/// Supported Keypair Algorithms
pub enum KeypairAlgorithm {
	Ed25519,
	EcdsaP256,
	EcdsaP384,
}

impl fmt::Display for KeypairAlgorithm {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			KeypairAlgorithm::Ed25519 => write!(f, "ed25519"),
			KeypairAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
			KeypairAlgorithm::EcdsaP384 => write!(f, "ecdsa-p384"),
		}
	}
}

impl KeypairAlgorithm {
	/// Return an `rcgen::KeyPair` for the given varient
	fn to_keypair(&self) -> Result<rcgen::KeyPair, rcgen::Error> {
		match self {
			KeypairAlgorithm::Ed25519 => {
				use ring::signature::Ed25519KeyPair;

				let rng = ring::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ED25519;
				let pkcs8_bytes =
					Ed25519KeyPair::generate_pkcs8(&rng).or(Err(rcgen::Error::RingUnspecified))?;

				rcgen::KeyPair::from_der_and_sign_algo(pkcs8_bytes.as_ref(), alg)
			},
			KeypairAlgorithm::EcdsaP256 => {
				use ring::signature::EcdsaKeyPair;
				use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;

				let rng = ring::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
				let pkcs8_bytes =
					EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
						.or(Err(rcgen::Error::RingUnspecified))?;
				rcgen::KeyPair::from_der_and_sign_algo(pkcs8_bytes.as_ref(), alg)
			},
			KeypairAlgorithm::EcdsaP384 => {
				use ring::signature::EcdsaKeyPair;
				use ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING;

				let rng = ring::rand::SystemRandom::new();
				let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
				let pkcs8_bytes =
					EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
						.or(Err(rcgen::Error::RingUnspecified))?;

				rcgen::KeyPair::from_der_and_sign_algo(pkcs8_bytes.as_ref(), alg)
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

		assert_eq!(end_entity.params.alg, &rcgen::PKCS_ECDSA_P256_SHA256);
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
			.signature_algorithm(&KeypairAlgorithm::EcdsaP384)?
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
			.signature_algorithm(&KeypairAlgorithm::Ed25519)?
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
		let cert = EndEntityBuilder::new(params);
		assert_eq!(cert.params.is_ca, IsCa::NoCa)
	}
	#[test]
	fn client_auth_end_entity() {
		let _ca = CertificateBuilder::new()
			.certificate_authority()
			.build()
			.unwrap();
		let params = CertificateParams::default();
		let mut cert = EndEntityBuilder::new(params);
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
		let mut cert = EndEntityBuilder::new(params);
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
		let names = vec![SanType::DnsName(name.into())];
		let params = CertificateParams::default();
		let cert = EndEntityBuilder::new(params).subject_alternative_names(names);
		assert_eq!(
			cert.params.subject_alt_names,
			vec![rcgen::SanType::DnsName(name.into())]
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
		let cert = EndEntityBuilder::new(params).subject_alternative_names(names);
		assert_eq!(cert.params.subject_alt_names, vec![]);
	}

	#[test]
	fn keypair_algorithm_to_keypair() -> anyhow::Result<()> {
		let keypair = KeypairAlgorithm::Ed25519.to_keypair()?;
		assert_eq!(format!("{:?}", keypair.algorithm()), "PKCS_ED25519");
		let keypair = KeypairAlgorithm::EcdsaP256.to_keypair()?;
		assert_eq!(
			format!("{:?}", keypair.algorithm()),
			"PKCS_ECDSA_P256_SHA256"
		);
		let keypair = KeypairAlgorithm::EcdsaP384.to_keypair()?;
		assert_eq!(
			format!("{:?}", keypair.algorithm()),
			"PKCS_ECDSA_P384_SHA384"
		);
		Ok(())
	}
}
