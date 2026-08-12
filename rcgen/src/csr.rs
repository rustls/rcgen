use std::hash::Hash;

#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::CertificateSigningRequestDer;

#[cfg(feature = "x509-parser")]
use crate::ext::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{
	Certificate, CertificateParams, Error, Issuer, PublicKeyData, SignatureAlgorithm, SigningKey,
};
#[cfg(feature = "x509-parser")]
use crate::{CustomExtension, DistinguishedName};

/// A public key, extracted from a CSR
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
	raw: Vec<u8>,
	alg: &'static SignatureAlgorithm,
}

impl PublicKey {
	/// The algorithm used to generate the public key and sign the CSR.
	pub fn algorithm(&self) -> &SignatureAlgorithm {
		self.alg
	}
}

impl PublicKeyData for PublicKey {
	fn der_bytes(&self) -> &[u8] {
		&self.raw
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.alg
	}
}

/// A certificate signing request (CSR) that can be encoded to PEM or DER.
///
/// A new certificate signing request is created by filling out a [`CertificateParams`] object
/// and then calling [`CertificateParams::serialize_request()`] or
/// [`CertificateParams::serialize_request_with_attributes()`] with a
/// [`crate::KeyPair`] (or other [`SigningKey`] capable trait).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSigningRequest {
	pub(crate) der: CertificateSigningRequestDer<'static>,
}

impl CertificateSigningRequest {
	/// Get the PEM-encoded bytes of the certificate signing request.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> Result<String, Error> {
		let p = Pem::new("CERTIFICATE REQUEST", &*self.der);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}

	/// Get the DER-encoded bytes of the certificate signing request.
	///
	/// [`CertificateSigningRequestDer`] implements `Deref<Target = [u8]>` and `AsRef<[u8]>`,
	/// so you can easily extract the DER bytes from the return value.
	pub fn der(&self) -> &CertificateSigningRequestDer<'static> {
		&self.der
	}
}

impl From<CertificateSigningRequest> for CertificateSigningRequestDer<'static> {
	fn from(csr: CertificateSigningRequest) -> Self {
		csr.der
	}
}

/// Parameters for a certificate signing request
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSigningRequestParams {
	/// Parameters for the certificate to be signed.
	pub params: CertificateParams,
	/// Public key to include in the certificate signing request.
	pub public_key: PublicKey,
}

impl CertificateSigningRequestParams {
	/// Parse and verify a certificate signing request from the ASCII PEM format
	///
	/// See [`from_der`](Self::from_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		let csr = pem::parse(pem_str).map_err(|_| Error::CouldNotParseCertificationRequest)?;
		Self::from_der(&csr.contents().into())
	}

	/// Parse and verify a certificate signing request from DER-encoded bytes
	///
	/// The following requested extensions are parsed natively into params:
	/// - `Subject Alternative Name` (see [`crate::SanType`])
	/// - `Key Usage` (see [`crate::KeyUsagePurpose`])
	/// - `Extended Key Usage` (see [`crate::ExtendedKeyUsagePurpose`])
	/// - `Basic Constraints` (see [`crate::PathLenConstraint`])
	///
	/// Any other requested extensions are preserved verbatim in
	/// [`CertificateParams::custom_extensions`] as [`CustomExtension`]s.
	/// If the request's signature is invalid, this function will return
	/// [`Error::InvalidCertificationRequestSignature`].
	///
	/// The [`PemObject`] trait is often used to obtain a [`CertificateSigningRequestDer`] from
	/// PEM input. If you already have a byte slice containing DER, it can trivially be converted
	/// into [`CertificateSigningRequestDer`] using the [`Into`] trait.
	///
	/// [`PemObject`]: pki_types::pem::PemObject
	#[cfg(feature = "x509-parser")]
	pub fn from_der(csr: &CertificateSigningRequestDer<'_>) -> Result<Self, Error> {
		use x509_parser::prelude::FromDer;

		let csr = x509_parser::certification_request::X509CertificationRequest::from_der(csr)
			.map_err(|_| Error::CouldNotParseCertificationRequest)?
			.1;
		csr.verify_signature()
			.map_err(|_| Error::InvalidCertificationRequestSignature)?;
		let alg_oid = csr
			.signature_algorithm
			.algorithm
			.iter()
			.ok_or(Error::CouldNotParseCertificationRequest)?
			.collect::<Vec<_>>();
		let alg = SignatureAlgorithm::from_oid(&alg_oid)?;

		let info = &csr.certification_request_info;
		let mut params = CertificateParams {
			distinguished_name: DistinguishedName::from_name(&info.subject)?,
			..CertificateParams::default()
		};
		let raw = info.subject_pki.subject_public_key.data.to_vec();

		let requested_extensions =
			info.iter_attributes()
				.find_map(|attr| match attr.parsed_attribute() {
					x509_parser::prelude::ParsedCriAttribute::ExtensionRequest(requested) => {
						Some(&requested.extensions)
					},
					_ => None,
				});

		if let Some(requested_extensions) = requested_extensions {
			for extension in requested_extensions {
				let parsed = extension.parsed_extension();
				let handled = KeyUsage::from_parsed(&mut params, parsed)?
					|| SubjectAlternativeName::from_parsed(&mut params, parsed)?
					|| ExtendedKeyUsage::from_parsed(&mut params, parsed)?
					|| BasicConstraints::from_parsed(&mut params, parsed)?;

				// Extensions that params can't represent natively are preserved
				// verbatim, so serializing the recovered params reproduces the
				// requested extensions.
				if !handled {
					params
						.custom_extensions
						.push(CustomExtension::from_parsed(extension)?);
				}
			}
		}

		Ok(Self {
			params,
			public_key: PublicKey { alg, raw },
		})
	}

	/// Generate a new certificate based on the requested parameters, signed by the provided
	/// issuer.
	///
	/// The returned certificate will have its issuer field set to the subject of the provided
	/// `issuer`, and the authority key identifier extension will be populated using the subject
	/// public key of `issuer`. It will be signed by `issuer_key`.
	///
	/// Note that no validation of the `issuer` certificate is performed. Rcgen will not require
	/// the certificate to be a CA certificate, or have key usage extensions that allow signing.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn signed_by(&self, issuer: &Issuer<impl SigningKey>) -> Result<Certificate, Error> {
		Ok(Certificate {
			der: self
				.params
				.serialize_der_with_signer(&self.public_key, issuer)?,
		})
	}
}

#[cfg(all(test, feature = "x509-parser"))]
mod tests {
	use x509_parser::certification_request::X509CertificationRequest;
	use x509_parser::prelude::{FromDer, ParsedExtension};

	use crate::{
		CertificateParams, CertificateSigningRequestParams, Criticality, CustomExtension,
		ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PathLenConstraint,
	};

	#[test]
	fn dont_write_sans_extension_if_no_sans_are_present() {
		let mut params = CertificateParams::default();
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		assert!(!parsed_csr
			.requested_extensions()
			.unwrap()
			.any(|ext| matches!(ext, ParsedExtension::SubjectAlternativeName(_))));
	}

	#[test]
	fn write_extension_request_if_ekus_are_present() {
		let mut params = CertificateParams::default();
		params
			.extended_key_usages
			.push(ExtendedKeyUsagePurpose::ClientAuth);
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		let requested_extensions = parsed_csr
			.requested_extensions()
			.unwrap()
			.collect::<Vec<_>>();
		assert!(matches!(
			requested_extensions.first().unwrap(),
			ParsedExtension::ExtendedKeyUsage(_)
		));
	}

	#[test]
	fn write_basic_constraints_if_present() {
		use x509_parser::extensions::BasicConstraints as B;

		let params = CertificateParams {
			is_ca: IsCa::ExplicitNoCa,
			..Default::default()
		};
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		let requested_extensions = parsed_csr
			.requested_extensions()
			.unwrap()
			.collect::<Vec<_>>();

		assert!(matches!(
			requested_extensions.first().unwrap(),
			ParsedExtension::BasicConstraints(B {
				ca: false,
				path_len_constraint: None
			})
		));
	}

	#[test]
	fn serialize_and_deserialize_eq_custom_extensions() {
		// Custom extensions must survive a serialize/parse round trip, preserving
		// OID, criticality and value. See rustls/rcgen#446 for context: rcgen
		// previously rejected CSRs containing extensions it wrote itself.
		let params = CertificateParams {
			custom_extensions: vec![
				CustomExtension::from_oid_content(
					&[1, 3, 6, 1, 4, 1, 99, 9],
					Criticality::Critical,
					vec![0x0C, 0x02, 0x68, 0x69],
				),
				CustomExtension::from_oid_content(
					&[1, 3, 6, 1, 4, 1, 99, 10],
					Criticality::NonCritical,
					vec![0x05, 0x00],
				),
			],
			..Default::default()
		};
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let csr_de = CertificateSigningRequestParams::from_der(csr.der()).unwrap();

		assert_eq!(csr_de.params.custom_extensions, params.custom_extensions);
	}

	#[test]
	fn serialize_and_deserialize_eq_other_eku() {
		// Custom EKU purpose OIDs must survive a serialize/parse round trip.
		let params = CertificateParams {
			extended_key_usages: vec![
				ExtendedKeyUsagePurpose::ServerAuth,
				ExtendedKeyUsagePurpose::Other(vec![1, 3, 6, 1, 4, 1, 99, 7]),
			],
			..Default::default()
		};
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let csr_de = CertificateSigningRequestParams::from_der(csr.der()).unwrap();

		assert_eq!(
			csr_de.params.extended_key_usages,
			params.extended_key_usages
		);
	}

	#[test]
	fn serialize_and_deserialize_eq_basic_constraints() {
		let params = CertificateParams {
			is_ca: IsCa::Ca(PathLenConstraint::Constrained(10)),
			..Default::default()
		};
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let csr_de = CertificateSigningRequestParams::from_der(csr.der()).unwrap();

		assert_eq!(csr_de.params.is_ca, params.is_ca);
	}
}
