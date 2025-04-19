#[cfg(feature = "x509-parser")]
use pki_types::CertificateDer;

use crate::{
	Certificate, CertificateParams, DistinguishedName, KeyIdMethod, KeyPair, KeyUsagePurpose,
	PublicKeyData, SignatureAlgorithm,
};

/// Holds the information necessary for an issuer of a certificate to sign other certificates. Specifically, it must
/// have the distinguished name, key identifier method, key usages, and access to the private key.
///
/// Optionally, the issuer may also have the entire issuer's certificate, but for root certificates this cannot be
/// available, as the root certificate is self-signed.
pub struct Issuer {
	/// The distinguished name of the issuer. Used to construct the issuer field in the issued certificate.
	pub(crate) distinguished_name: DistinguishedName,

	/// The method used to generate the key identifier for the issuer. Must match the method used to generate the
	/// subject key identifier in the issuer's certificate.
	pub(crate) key_identifier_method: KeyIdMethod,

	/// The key usage purposes associated with the issuer.
	pub(crate) key_usages: Vec<KeyUsagePurpose>,

	/// The key pair of the issuer which includes the private key, though it may be a RemoteKeyPair allowing for a key
	/// held in an HSM or other secure location to sign the certificate.
	pub(crate) key_pair: KeyPair,

	/// The issuer's certificate, if available. This is typically `None` for root certificates.
	pub(crate) certificate: Option<Certificate>,
}

impl Issuer {
	/// Creates a new issuer from a certificate in DER format and a key pair. The certificate must be a CA certificate
	/// and the key pair must contain the private key associated with the certificate.
	#[cfg(feature = "x509-parser")]
	pub fn new(der: &CertificateDer, key_pair: &KeyPair) -> Result<Self, crate::Error> {
		// TODO: The certificate contains the public key, which must match the public key in the key pair, or this
		// issuer is invalid. We should check this error condition.

		let params = CertificateParams::from_ca_cert_der(der)?;
		let certificate = Certificate {
			params: params.clone(),
			subject_public_key_info: key_pair.public_key_der(),
			der: der.clone().into_owned(),
		};

		Ok(Self {
			distinguished_name: params.distinguished_name,
			key_identifier_method: params.key_identifier_method,
			key_usages: params.key_usages,
			key_pair: key_pair.clone(),
			certificate: Some(certificate),
		})
	}

	/// Creates a new issuer from the given parameters and key pair. This is typically used for root certificates, which
	/// do not initially have a certificate.
	pub fn new_from_params(params: &CertificateParams, key_pair: &KeyPair) -> Self {
		Self {
			distinguished_name: params.distinguished_name.clone(),
			key_identifier_method: params.key_identifier_method.clone(),
			key_usages: params.key_usages.clone(),
			key_pair: key_pair.clone(),
			certificate: None,
		}
	}

	/// Sets the certificate of the issuer.
	pub fn set_certificate(&mut self, certificate: Certificate) {
		self.certificate = Some(certificate);
	}

	/// Returns the certificate of the issuer, if available. This is typically `None` for root certificates issuers
	pub fn certificate(&self) -> Option<&Certificate> {
		self.certificate.as_ref()
	}

	/// Returns the distinguished name of the issuer.
	pub fn distinguished_name(&self) -> &DistinguishedName {
		&self.distinguished_name
	}

	/// Returns the public key of the issuer
	pub fn public_key_raw(&self) -> &[u8] {
		&self.key_pair.public_key_raw()
	}

	/// Returns the public key of the issuer in der format
	pub fn public_key_der(&self) -> Vec<u8> {
		self.key_pair.public_key_der()
	}

	/// Returns the private key of the issuer. The caller had access to this key when creating the issuer, so it is not
	/// an increase in privilege to return it.
	pub fn key_pair(&self) -> &KeyPair {
		&self.key_pair
	}
}

impl PublicKeyData for Issuer {
	fn der_bytes(&self) -> &[u8] {
		self.key_pair.der_bytes()
	}

	fn algorithm(&self) -> &SignatureAlgorithm {
		self.key_pair.algorithm()
	}
}
