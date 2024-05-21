use pki_types::CertificateDer;

use crate::{
	Certificate, CertificateParams, DistinguishedName, Error, KeyIdMethod, KeyPair, KeyUsagePurpose,
};

/// TODO
pub struct Issuer {
	pub(crate) distinguished_name: DistinguishedName,
	pub(crate) key_identifier_method: KeyIdMethod,
	pub(crate) key_usages: Vec<KeyUsagePurpose>,
	pub(crate) key_pair: KeyPair,
}

impl Issuer {
	/// TODO
	pub fn new(ca_cert: CertificateDer, key_pair: KeyPair) -> Result<Self, Error> {
		let params = CertificateParams::from_ca_cert_der(&ca_cert)?;
		Ok(Self {
			distinguished_name: params.distinguished_name,
			key_identifier_method: params.key_identifier_method,
			key_usages: params.key_usages,
			key_pair,
		})
	}

	/// TODO
	pub fn from_params(params: CertificateParams, key_pair: KeyPair) -> Self {
		Self {
			distinguished_name: params.distinguished_name,
			key_identifier_method: params.key_identifier_method,
			key_usages: params.key_usages,
			key_pair,
		}
	}

	/// TODO
	pub fn certificate(&self) -> Certificate {
		// let params = CertificateParams::from_ca_cert_der(&der)?;
		// Ok(Certificate {
		// 	params,
		// 	subject_public_key_info: keypair.public_key_der(),
		// 	der,
		// })
		todo!();
	}

	/// TODO
	pub fn pem(&self) -> String {
		todo!();
	}

	/// TODO
	pub fn key_pair(&self) -> &KeyPair {
		&self.key_pair
	}
}
