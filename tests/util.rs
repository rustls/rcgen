extern crate rcgen;

use rcgen::{CertificateParams, DnType};

pub fn default_params() -> CertificateParams {
	let mut params = CertificateParams::new(vec![
		"crabs.crabs".to_string(), "localhost".to_string(),
	]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master CA");
	params
}
