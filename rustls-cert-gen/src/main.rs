use rustls_cert_gen::{CertificateBuilder, Result};
mod args;

fn main() -> Result<()> {
	let opts = args::options().run();

	let ca = CertificateBuilder::new()
		.signature_algorithm(&opts.sig_algo)?
		.certificate_authority()
		.country_name(&opts.country_name)
		.organization_name(&opts.organization_name)
		.build()?;

	let mut entity = CertificateBuilder::new()
		.signature_algorithm(&opts.sig_algo)?
		.end_entity()
		.common_name(&opts.common_name)
		.subject_alternative_names(opts.san);

	if opts.client_auth {
		entity.client_auth();
	};

	if opts.server_auth {
		entity.server_auth();
	};

	entity
		.build()?
		.serialize_pem(ca.cert())?
		.write(&opts.output, &opts.cert_file_name)?;

	ca.serialize_pem()?
		.write(&opts.output, &opts.ca_file_name)?;

	Ok(())
}
