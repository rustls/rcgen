use rcgen::{
	BasicConstraints, Certificate, CertificateParams, DnType, DnValue::PrintableString, IsCa,
	KeyUsagePurpose,
};

use super::PemCertifiedKey;

pub struct CaParams {
	params: CertificateParams,
}

impl CaParams {
	pub fn new(mut params: CertificateParams) -> Self {
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		params.key_usages.push(KeyUsagePurpose::KeyCertSign);
		params.key_usages.push(KeyUsagePurpose::CrlSign);
		Self { params }
	}
	/// Return `&self.params`.
	pub fn params(&self) -> &CertificateParams {
		&self.params
	}
	pub fn country_name(mut self, country: &str) -> Self {
		self.params
			.distinguished_name
			.push(DnType::CountryName, PrintableString(country.into()));
		self
	}
	pub fn organization_name(mut self, name: &str) -> Self {
		self.params
			.distinguished_name
			.push(DnType::OrganizationName, name);
		self
	}
	pub fn build(self) -> Result<Ca, rcgen::Error> {
		let cert = Certificate::from_params(self.params)?;
		let cert = Ca { cert };
		Ok(cert)
	}
}

pub struct Ca {
	cert: Certificate,
}

impl Ca {
	/// Self-sign and serialize
	pub fn serialize_pem(&self) -> Result<PemCertifiedKey, rcgen::Error> {
		let cert_pem = self.cert.serialize_pem()?;
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn init_ca() {
		let params = CertificateParams::default();
		let cert = CaParams::new(params);
		assert_eq!(
			cert.params().is_ca,
			IsCa::Ca(BasicConstraints::Unconstrained)
		)
	}
}
