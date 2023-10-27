use rcgen::{CertificateParams, DistinguishedName};

use super::{ca::CaParams, entity::EndEntityParams, signature::Signature};

/// Builder to configure TLS [CertificateParams] to be finalized
/// into either a Ca or an End-Entity.
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
	/// Set signature algorithm (instead of default). Returns `crate::Result<Self>`.
	/// # Example
	/// ```
	/// # use rustls_cert_gen::CertificateBuilder;
	/// let cert = CertificateBuilder::new().signature_algorithm("ed25519");
	/// ```
	pub fn signature_algorithm(mut self, alg: &str) -> crate::Result<Self> {
		let sig = Signature::new(alg)?;
		self.params.alg = sig.key_pair.algorithm();
		self.params.key_pair = Some(sig.key_pair);
		Ok(self)
	}
	/// Set options for Ca Certificates
	/// # Example
	/// ```
	/// # use rustls_cert_gen::CertificateBuilder;
	/// let cert = CertificateBuilder::new().certificate_authority();
	/// ```
	pub fn certificate_authority(self) -> CaParams {
		CaParams::new(self.params)
	}
	/// Set options for `EndEntity` Certificates
	pub fn end_entity(self) -> EndEntityParams {
		EndEntityParams::new(self.params)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rcgen::{BasicConstraints, IsCa};
	use x509_parser::prelude::{FromDer, X509Certificate};

	#[test]
	fn init_ca() {
		let cert = CertificateBuilder::new().certificate_authority();
		assert_eq!(
			cert.params().is_ca,
			IsCa::Ca(BasicConstraints::Unconstrained)
		)
	}
	#[test]
	fn with_sig_algo_default() -> crate::Result<()> {
		let end_entity = CertificateBuilder::new().end_entity();

		assert_eq!(end_entity.params().alg, &rcgen::PKCS_ECDSA_P256_SHA256);
		Ok(())
	}
	#[test]
	fn serialize_end_entity_default_sig() -> crate::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.end_entity()
			.build()?
			.serialize_pem(ca.cert())?;

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem()?.cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		assert!(!cert.is_ca());
		check_signature(&cert, &issuer);

		Ok(())
	}
	#[test]
	fn serialize_end_entity_ecdsa_p384_sha384_sig() -> crate::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.signature_algorithm("ECDSA_P384")?
			.end_entity()
			.build()?
			.serialize_pem(ca.cert())?;

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem()?.cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		check_signature(&cert, &issuer);
		Ok(())
	}

	#[test]
	fn serialize_end_entity_ed25519_sig() -> crate::Result<()> {
		let ca = CertificateBuilder::new().certificate_authority().build()?;
		let end_entity = CertificateBuilder::new()
			.signature_algorithm("ED25519")?
			.end_entity()
			.build()?
			.serialize_pem(ca.cert())?;

		let der = pem::parse(end_entity.cert_pem)?;
		let (_, cert) = X509Certificate::from_der(der.contents())?;

		let issuer_der = pem::parse(ca.serialize_pem()?.cert_pem)?;
		let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

		check_signature(&cert, &issuer);
		Ok(())
	}
	pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) {
		let verified = cert.verify_signature(Some(issuer.public_key())).is_ok();
		assert!(verified);
	}
}
