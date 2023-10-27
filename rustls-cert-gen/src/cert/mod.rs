use std::{fs::File, io, path::Path};

mod params;
pub use params::CertificateBuilder;
mod ca;
#[allow(unused_imports)]
pub use ca::{Ca, CaParams};
mod entity;
#[allow(unused_imports)]
pub use entity::{EndEntity, EndEntityParams};
mod signature;

#[derive(Debug, Clone)]
/// Pem serialized Certificate and Pem serialized corresponding private key
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

#[cfg(test)]
mod tests {
	use crate::cert::PemCertifiedKey;

	#[test]
	fn test_write_files() -> crate::Result<()> {
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
}
