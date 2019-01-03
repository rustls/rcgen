extern crate rcgen;
extern crate chrono;

use chrono::NaiveDate;
use rcgen::{Certificate, CertificateParams, PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION};

fn main() {
	let not_before = NaiveDate::from_ymd(2000, 01, 01).and_hms_milli(0, 0, 0, 0);
	let not_after = NaiveDate::from_ymd(2020, 01, 01).and_hms_milli(0, 0, 0, 0);
	let params = CertificateParams {
		alg : PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION,
		not_before,
		not_after,
		serial_number : None,
		subject_alt_names : vec!["crabs.crabs".to_string()],
	};
	let cert = Certificate::from_params(params);
	println!("{}", cert.serialize_pem());
	println!("{}", cert.serialize_private_key_pem());
}
