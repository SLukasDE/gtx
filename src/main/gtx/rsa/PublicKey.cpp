#include <gtx/rsa/PublicKey.h>

namespace gtx {
namespace rsa {

std::unique_ptr<PublicKey> PublicKey::create(const std::string& exponentStr, const std::string& modulusStr) {
	int rc;

	gnutls_datum_t exponent;
	exponent.data = reinterpret_cast<unsigned char*>(const_cast<char*>(exponentStr.c_str()));
	exponent.size = static_cast<unsigned int>(exponentStr.size());

	gnutls_datum_t modulus;
	modulus.data = reinterpret_cast<unsigned char*>(const_cast<char*>(modulusStr.c_str()));
	modulus.size = static_cast<unsigned int>(modulusStr.size());

	gnutls_pubkey_t publicKey = nullptr;
	rc = gnutls_pubkey_init(&publicKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pubkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_pubkey_import_rsa_raw(publicKey, &modulus, &exponent);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(publicKey);
		throw std::runtime_error("Error gnutls_pubkey_import_rsa_raw: " + std::string(gnutls_strerror (rc)));
	}

	return std::unique_ptr<PublicKey>(new PublicKey(publicKey));
}

const std::string& PublicKey::getModulus() const {
	return getParameters().modulus;
}

const std::string& PublicKey::getExponent() const {
	return getParameters().exponent;
}

const PublicKey::Parameters& PublicKey::getParameters() const {
	if(!parameters) {
		int rc;
		gnutls_datum_t exponent;
		gnutls_datum_t modulus;

		rc = gnutls_pubkey_export_rsa_raw(getPublicKey(), &modulus, &exponent);
		if(rc != GNUTLS_E_SUCCESS) {
			throw std::runtime_error("Error gnutls_pubkey_export_rsa_raw: " + std::string(gnutls_strerror(rc)));
		}

		parameters.reset(new Parameters);

		parameters->modulus = std::string(reinterpret_cast<char*>(modulus.data), modulus.size);
		gnutls_free(modulus.data);

		parameters->exponent = std::string(reinterpret_cast<char*>(exponent.data), exponent.size);
		gnutls_free(exponent.data);
	}

	return *parameters;
}

} /* namespace rsa */
} /* namespace gtx */
