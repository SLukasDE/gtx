#include <gtx/PrivateKey.h>
#include <gtx/PublicKey.h>
#include <gtx/ec/PrivateKey.h>
#include <gtx/rsa/PrivateKey.h>

#include <gnutls/abstract.h>

#include <vector>
#include <stdexcept>

namespace gtx {

namespace {
gnutls_digest_algorithm_t getDigestAlgorithm(const std::string& algorithmStr) {
	if(algorithmStr == "RS256") {
		return GNUTLS_DIG_SHA256;
	}
	else if(algorithmStr == "RS384") {
		return GNUTLS_DIG_SHA384;
	}
	else if(algorithmStr == "RS512") {
		return GNUTLS_DIG_SHA512;
	}

	return GNUTLS_DIG_UNKNOWN;
}
} /* anonymous namespace */

PrivateKey::~PrivateKey() {
	if(privateKey) {
		gnutls_privkey_deinit(privateKey);
	}

	if(privateKeyX509) {
		gnutls_x509_privkey_deinit(privateKeyX509);
	}
}

std::unique_ptr<PrivateKey> PrivateKey::createX509_DER(const std::string& privateKeyStr, const std::string& password) {
	return createX509(privateKeyStr, password, GNUTLS_X509_FMT_DER);
}

std::unique_ptr<PrivateKey> PrivateKey::createX509_PEM(const std::string& privateKeyStr, const std::string& password) {
	return createX509(privateKeyStr, password, GNUTLS_X509_FMT_PEM);
}

std::unique_ptr<PrivateKey> PrivateKey::createEC(gnutls_ecc_curve_t curveType, const std::string& curveKey, const std::string& coordinateX, const std::string& coordinateY) {
	return std::unique_ptr<PrivateKey>(ec::PrivateKey::create(curveType, curveKey, coordinateX, coordinateY).release());
}

std::unique_ptr<PrivateKey> PrivateKey::createRSA(const std::string& publicExponent, const std::string& privateExponent, const std::string& modulus, const std::string& primeP, const std::string& primeQ, const std::string& coefficient) {
	return std::unique_ptr<PrivateKey>(rsa::PrivateKey::create(publicExponent, privateExponent, modulus, primeP, primeQ, coefficient).release());
}

std::unique_ptr<PrivateKey> PrivateKey::createRSA(unsigned int bits) {
	return std::unique_ptr<PrivateKey>(rsa::PrivateKey::create(bits).release());
}

std::string PrivateKey::getX509_PRIVATE_KEY_DER(const std::string& password) const {
	return getX509_PRIVATE_KEY(password, GNUTLS_X509_FMT_DER);
}

std::string PrivateKey::getX509_PRIVATE_KEY_PEM(const std::string& password) const {
	return getX509_PRIVATE_KEY(password, GNUTLS_X509_FMT_PEM);
}

std::unique_ptr<PublicKey> PrivateKey::createPublicKey() {
	gnutls_pubkey_t publicKey = nullptr;
	int rc = gnutls_pubkey_init(&publicKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pubkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_pubkey_import_privkey(publicKey, privateKey, 0, 0);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(publicKey);
		throw std::runtime_error("Error gnutls_pubkey_import_privkey: " + std::string(gnutls_strerror(rc)));
	}

	return std::unique_ptr<PublicKey>(new PublicKey(publicKey));
}

std::string PrivateKey::getAlgorithmName() const {
	return gnutls_pk_algorithm_get_name(static_cast<gnutls_pk_algorithm_t>(gnutls_privkey_get_pk_algorithm(privateKey, NULL)));
}

unsigned int PrivateKey::getAlgorithmBits() const {
	unsigned int bits;
	if(gnutls_privkey_get_pk_algorithm(privateKey, &bits) == GNUTLS_PK_UNKNOWN) {
		throw std::runtime_error("Error gnutls_privkey_get_pk_algorithm: private key is unknown");
	}
	return bits;
}

std::string PrivateKey::decrypt(const std::string& ciphertextStr) const {
	int rc;

	gnutls_datum_t ciphertext;
	ciphertext.data = reinterpret_cast<unsigned char*>(const_cast<char*>(ciphertextStr.c_str()));
	ciphertext.size = static_cast<unsigned int>(ciphertextStr.size());

	gnutls_datum_t plaintext;

	rc = gnutls_privkey_decrypt_data(privateKey, 0, &ciphertext, &plaintext);
	if(rc < 0) {
		throw std::runtime_error("Error gnutls_privkey_decrypt_data: " + std::string(gnutls_strerror (rc)));
	}

	std::string plaintextStr(reinterpret_cast<char*>(plaintext.data), plaintext.size);
	gnutls_free(plaintext.data);

	return plaintextStr;
}

std::string PrivateKey::sign(const std::string& dataStr, const std::string& algorithmStr) const {
	int rc;

	gnutls_datum_t data;
	data.data = reinterpret_cast<unsigned char*>(const_cast<char*>(dataStr.c_str()));
	data.size = static_cast<unsigned int>(dataStr.size());

	gnutls_digest_algorithm_t digestAlgorithm = getDigestAlgorithm(algorithmStr);
	if(digestAlgorithm == GNUTLS_DIG_UNKNOWN) {
		throw std::runtime_error("Unknown digest algorithm \"" + algorithmStr + "\"");
	}

	/* Sign data */
	gnutls_datum_t signedData;
	rc = gnutls_privkey_sign_data(privateKey, digestAlgorithm, 0, &data, &signedData);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_privkey_sign_data: " + std::string(gnutls_strerror(rc)));
	}

	std::string signedDataStr(reinterpret_cast<char*>(signedData.data), signedData.size);
	gnutls_free(signedData.data);

	return signedDataStr;
}

PrivateKey::PrivateKey(gnutls_privkey_t aPrivateKey, gnutls_x509_privkey_t aPrivateKeyX509)
: privateKey(aPrivateKey),
  privateKeyX509(aPrivateKeyX509)
{
}

gnutls_privkey_t PrivateKey::getPrivateKey() const {
	return privateKey;
}

std::unique_ptr<PrivateKey> PrivateKey::createX509(const std::string& privateKeyStr, const std::string& passwordStr, gnutls_x509_crt_fmt_t encoding) {
	int rc;

	gnutls_x509_privkey_t privateKeyX509 = nullptr;
	if(gnutls_x509_privkey_init(&privateKeyX509)) {
		throw std::runtime_error("Error gnutls_x509_privkey_init: no memory");
	}

	gnutls_datum_t privateKeyDatum;
	privateKeyDatum.data = reinterpret_cast<unsigned char*>(const_cast<char*>(privateKeyStr.c_str()));
	privateKeyDatum.size = static_cast<unsigned int>(privateKeyStr.size());

	const char* password = passwordStr.empty() ? nullptr : passwordStr.c_str();

	rc = gnutls_x509_privkey_import2(privateKeyX509, &privateKeyDatum, encoding, password, 0);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(privateKeyX509);
		throw std::runtime_error("Error gnutls_x509_privkey_import: " + std::string(gnutls_strerror(rc)));
	}
/*
	rc = gnutls_x509_privkey_get_pk_algorithm(privateKeyX509);
	if(rc < 0) {
		gnutls_x509_privkey_deinit(privateKeyX509);
		throw std::runtime_error("Error gnutls_x509_privkey_get_pk_algorithm: " + std::string(gnutls_strerror(rc)));
	}
	gnutls_pk_algorithm_t algorithm = static_cast<gnutls_pk_algorithm_t>(rc);
*/
	gnutls_privkey_t privateKey = nullptr;
	rc = gnutls_privkey_init(&privateKey);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(privateKeyX509);
		throw std::runtime_error("Error gnutls_privkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_privkey_import_x509(privateKey, privateKeyX509, 0);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(privateKey);
		gnutls_x509_privkey_deinit(privateKeyX509);
		throw std::runtime_error("Error gnutls_privkey_import_x509: " + std::string(gnutls_strerror(rc)));
	}

	switch(static_cast<gnutls_pk_algorithm_t>(gnutls_privkey_get_pk_algorithm(privateKey, NULL))) {
	case GNUTLS_PK_RSA:
		return std::unique_ptr<PrivateKey>(new rsa::PrivateKey(privateKey, privateKeyX509));
	case GNUTLS_PK_EC:
		return std::unique_ptr<PrivateKey>(new ec::PrivateKey(privateKey, privateKeyX509));
	default:
		break;
	}

	return std::unique_ptr<PrivateKey>(new PrivateKey(privateKey, privateKeyX509));
}

std::string PrivateKey::getX509_PRIVATE_KEY(const std::string& passwordStr, gnutls_x509_crt_fmt_t encoding) const {
	int rc;

	const char* password = passwordStr.empty() ? nullptr : passwordStr.c_str();

	if(!privateKeyX509) {
#if 0
		int rc;

		gnutls_x509_privkey_t privateKeyX509 = nullptr;
		rc = gnutls_x509_privkey_init(&privateKeyX509);
		if(rc != GNUTLS_E_SUCCESS) {
			throw std::runtime_error("Error gnutls_x509_privkey_init: " + std::string(gnutls_strerror(rc)));
		}

		rc = gnutls_privkey_export_x509(privateKeyX509, privateKey);
		if(rc != GNUTLS_E_SUCCESS) {
			gnutls_x509_privkey_deinit(privateKeyX509);
			throw std::runtime_error("Error gnutls_privkey_export_x509: " + std::string(gnutls_strerror(rc)));
		}

		std::string privateKeyStr = gtx::PrivateKey::getX509_PRIVATE_KEY(privateKeyX509, passwordStr, encoding);

		gnutls_x509_privkey_deinit(privateKeyX509);
		return privateKeyStr;
#else
		return "";
#endif
	}

	gnutls_datum_t pkcs8Datum;
	rc = gnutls_x509_privkey_export2_pkcs8(privateKeyX509, encoding, password, 0, &pkcs8Datum);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_x509_privkey_export2_pkcs8: " + std::string(gnutls_strerror(rc)));
	}

	std::string pkcs8Str(reinterpret_cast<char*>(pkcs8Datum.data), pkcs8Datum.size);
	gnutls_free(pkcs8Datum.data);

	return pkcs8Str;
}

} /* namespace gtx */
