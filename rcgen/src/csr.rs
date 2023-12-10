#[cfg(feature = "x509-parser")]
use crate::{ext, DistinguishedName};
#[cfg(feature = "pem")]
use pem::Pem;
use std::hash::Hash;

use crate::{Certificate, CertificateParams, Error, PublicKeyData, SignatureAlgorithm};

/// A public key, extracted from a CSR
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
	raw: Vec<u8>,
	alg: &'static SignatureAlgorithm,
}

impl PublicKeyData for PublicKey {
	fn alg(&self) -> &SignatureAlgorithm {
		self.alg
	}

	fn raw_bytes(&self) -> &[u8] {
		&self.raw
	}
}

/// Data for a certificate signing request
pub struct CertificateSigningRequest {
	/// Parameters for the certificate to be signed.
	pub params: CertificateParams,
	/// Public key to include in the certificate signing request.
	pub public_key: PublicKey,
}

impl CertificateSigningRequest {
	/// Parse a certificate signing request from the ASCII PEM format
	///
	/// See [`from_der`](Self::from_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		let csr = pem::parse(pem_str).or(Err(Error::CouldNotParseCertificationRequest))?;
		Self::from_der(csr.contents())
	}

	/// Parse a certificate signing request from DER-encoded bytes
	///
	/// Currently, this only supports the `Subject Alternative Name` extension.
	/// On encountering other extensions, this function will return an error.
	#[cfg(feature = "x509-parser")]
	pub fn from_der(csr: &[u8]) -> Result<Self, Error> {
		use x509_parser::prelude::FromDer;
		let csr = x509_parser::certification_request::X509CertificationRequest::from_der(csr)
			.map_err(|_| Error::CouldNotParseCertificationRequest)?
			.1;
		csr.verify_signature().map_err(|_| Error::RingUnspecified)?;
		let alg_oid = csr
			.signature_algorithm
			.algorithm
			.iter()
			.ok_or(Error::CouldNotParseCertificationRequest)?
			.collect::<Vec<_>>();
		let alg = SignatureAlgorithm::from_oid(&alg_oid)?;

		let info = &csr.certification_request_info;
		let mut params = CertificateParams::default();
		params.alg = alg;
		params.distinguished_name = DistinguishedName::from_name(&info.subject)?;
		let raw = info.subject_pki.subject_public_key.data.to_vec();

		if let Some(extensions) = csr.requested_extensions() {
			for ext in extensions {
				match ext::SubjectAlternativeName::from_parsed(&mut params, ext) {
					Ok(true) => continue, // SAN extension handled.
					Err(err) => return Err(err),
					_ => {}, // Not a SAN.
				}
				match ext::KeyUsage::from_parsed(&mut params, ext) {
					Ok(true) => continue, // KU extension handled.
					Err(err) => return Err(err),
					_ => {}, // Not a KU.
				}
				match ext::ExtendedKeyUsage::from_parsed(&mut params, ext) {
					Ok(true) => continue, // EKU extension handled.
					Err(err) => return Err(err),
					_ => {}, // Not an EKU.
				}
				match ext::NameConstraints::from_parsed(&mut params, ext) {
					Ok(true) => continue, // NC extension handled.
					Err(err) => return Err(err),
					_ => {}, // Not an NC.
				}

				// If we get here, we've encountered an unknown and unhandled extension.
				return Err(Error::UnsupportedExtension);
			}
		}

		// Not yet handled:
		// * is_ca
		// and any other extensions.

		Ok(Self {
			params,
			public_key: PublicKey { alg, raw },
		})
	}
	/// Serializes the requested certificate, signed with another certificate's key, in binary DER format
	pub fn serialize_der_with_signer(&self, ca: &Certificate) -> Result<Vec<u8>, Error> {
		self.params.serialize_der_with_signer(&self.public_key, ca)
	}
	/// Serializes the requested certificate, signed with another certificate's key, to the ASCII PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca: &Certificate) -> Result<String, Error> {
		let contents = self
			.params
			.serialize_der_with_signer(&self.public_key, ca)?;
		let p = Pem::new("CERTIFICATE", contents);
		Ok(pem::encode_config(&p, crate::ENCODE_CONFIG))
	}
}
