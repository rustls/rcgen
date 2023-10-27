use super::PemCertifiedKey;
use rcgen::{
	Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};

/// End-entity [Certificate]
pub struct EndEntity {
	cert: Certificate,
}

impl EndEntity {
	/// Sign with `self.signer` and serialize.
	pub fn serialize_pem(&self, signer: &Certificate) -> Result<PemCertifiedKey, rcgen::Error> {
		let cert_pem = self.cert.serialize_pem_with_signer(signer)?;
		let key_pem = self.cert.serialize_private_key_pem();
		Ok(PemCertifiedKey {
			cert_pem,
			private_key_pem: key_pem,
		})
	}
	pub fn cert(&self) -> &Certificate {
		&self.cert
	}
}

/// [CertificateParams] from which an [EndEntity] [Certificate] can be built
pub struct EndEntityParams {
	params: CertificateParams,
}

impl EndEntityParams {
	/// Initialize `EndEntityParams`
	pub fn new(mut params: CertificateParams) -> Self {
		params.is_ca = IsCa::NoCa;
		params.use_authority_key_identifier_extension = true;
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		Self { params }
	}
	/// Return `&self.params`.
	pub fn params(&self) -> &CertificateParams {
		&self.params
	}
	pub fn common_name(mut self, name: &str) -> Self {
		self.params
			.distinguished_name
			.push(DnType::CommonName, name);
		self
	}
	/// `SanTypes` that will be recorded as `subject_alt_names`
	pub fn subject_alternative_names(mut self, sans: Vec<SanType>) -> Self {
		for san in sans {
			self.params.subject_alt_names.push(san);
		}
		self
	}
	/// Add ClientAuth to `extended_key_usages`.
	pub fn client_auth(&mut self) -> &Self {
		let usage = ExtendedKeyUsagePurpose::ClientAuth;
		self.params.extended_key_usages.push(usage);
		self
	}
	/// Add ServerAuth to `extended_key_usages`.
	pub fn server_auth(&mut self) -> &Self {
		let usage = ExtendedKeyUsagePurpose::ServerAuth;
		self.params.extended_key_usages.push(usage);
		self
	}
	pub fn build(self) -> Result<EndEntity, rcgen::Error> {
		let cert = Certificate::from_params(self.params)?;
		let cert = EndEntity { cert };
		Ok(cert)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::CertificateBuilder;
	use rcgen::{ExtendedKeyUsagePurpose, IsCa};
	#[test]
	fn init_end_endity() {
		let params = CertificateParams::default();
		let cert = EndEntityParams::new(params);
		assert_eq!(cert.params().is_ca, IsCa::NoCa)
	}
	#[test]
	fn client_auth_end_entity() {
		let _ca = CertificateBuilder::new()
			.certificate_authority()
			.build()
			.unwrap();
		let params = CertificateParams::default();
		let mut cert = EndEntityParams::new(params);
		assert_eq!(cert.params().is_ca, IsCa::NoCa);
		assert_eq!(
			cert.client_auth().params().extended_key_usages,
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
		let mut cert = EndEntityParams::new(params);
		assert_eq!(cert.params().is_ca, IsCa::NoCa);
		assert_eq!(
			cert.server_auth().params().extended_key_usages,
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
		let cert = EndEntityParams::new(params).subject_alternative_names(names);
		assert_eq!(
			cert.params().subject_alt_names,
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
		let cert = EndEntityParams::new(params).subject_alternative_names(names);
		assert_eq!(cert.params().subject_alt_names, vec![]);
	}
}
