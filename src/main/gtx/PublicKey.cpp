#include <gtx/PublicKey.h>
#include <gtx/ec/PublicKey.h>
#include <gtx/rsa/PublicKey.h>
//#include <gtx/Logger.h>

#include <vector>
#include <stdexcept>

namespace gtx {

namespace {
gnutls_sign_algorithm_t getSignAlgorithm(const std::string& algorithmStr) {
	if(algorithmStr == "RS256") {
		return GNUTLS_SIGN_RSA_SHA256;
	}
	else if(algorithmStr == "ES256") {
		return GNUTLS_SIGN_ECDSA_SHA256;
	}
	else if(algorithmStr == "RS384") {
		return GNUTLS_SIGN_RSA_SHA384;
	}
	else if(algorithmStr == "ES384") {
		return GNUTLS_SIGN_ECDSA_SHA384;
	}
	else if(algorithmStr == "RS512") {
		return GNUTLS_SIGN_RSA_SHA512;
	}
	else if(algorithmStr == "ES512") {
		return GNUTLS_SIGN_ECDSA_SHA512;
	}

	return GNUTLS_SIGN_UNKNOWN;
}
//Logger logger("gtx::PublicKey");
} /* anonymous namespace */


PublicKey::~PublicKey() {
	if(certificate) {
		gnutls_pcert_deinit(certificate.get());
		//publicKey = nullptr;
	}
	else if(publicKey) {
		gnutls_pubkey_deinit(publicKey);
	}
}

std::unique_ptr<PublicKey> PublicKey::createX509_PUBLIC_KEY_DER(const std::string& publicKey) {
	return createX509_PUBLIC_KEY(publicKey, GNUTLS_X509_FMT_DER);
}

std::unique_ptr<PublicKey> PublicKey::createX509_PUBLIC_KEY_PEM(const std::string& publicKey) {
	return createX509_PUBLIC_KEY(publicKey, GNUTLS_X509_FMT_PEM);
}

std::unique_ptr<PublicKey> PublicKey::createX509_CERTIFICATE_DER(const std::string& certificate) {
	return createX509_CERTIFICATE(certificate, GNUTLS_X509_FMT_DER);
}

std::unique_ptr<PublicKey> PublicKey::createX509_CERTIFICATE_PEM(const std::string& certificate) {
	return createX509_CERTIFICATE(certificate, GNUTLS_X509_FMT_PEM);
}

std::unique_ptr<PublicKey> PublicKey::createEC(gnutls_ecc_curve_t curveType, const std::string& coordinateX, const std::string& coordinateY) {
	return std::unique_ptr<PublicKey>(ec::PublicKey::create(curveType, coordinateX, coordinateY).release());
}

std::unique_ptr<PublicKey> PublicKey::createRSA(const std::string& exponent, const std::string& modulus) {
	return std::unique_ptr<PublicKey>(rsa::PublicKey::create(exponent, modulus).release());
}

std::string PublicKey::getX509_PUBLIC_KEY_DER() const {
	return getX509_PUBLIC_KEY(GNUTLS_X509_FMT_DER);
}

std::string PublicKey::getX509_PUBLIC_KEY_PEM() const {
	return getX509_PUBLIC_KEY(GNUTLS_X509_FMT_PEM);
}


std::string PublicKey::getAlgorithmName() const {
	return gnutls_pk_algorithm_get_name(static_cast<gnutls_pk_algorithm_t>(gnutls_pubkey_get_pk_algorithm(publicKey, NULL)));
}

unsigned int PublicKey::getAlgorithmBits() const {
	unsigned int bits;
	if(gnutls_pubkey_get_pk_algorithm(publicKey, &bits) == GNUTLS_PK_UNKNOWN) {
		throw std::runtime_error("Error gnutls_pubkey_get_pk_algorithm: private key is not a RSA key");
	}
	return bits;
}

std::string PublicKey::getPrettyPrint(bool b) const {
	gnutls_datum_t prettyPrint;
	int rc = gnutls_pubkey_print(publicKey, b ? GNUTLS_CRT_PRINT_FULL_NUMBERS : GNUTLS_CRT_PRINT_FULL, &prettyPrint);

	if(rc != GNUTLS_E_SUCCESS) {
		return "(no data)";
	}

	std::string prettyPrintStr(reinterpret_cast<char*>(prettyPrint.data), prettyPrint.size);
	gnutls_free(prettyPrint.data);

	return prettyPrintStr;
}

std::string PublicKey::encrypt(const std::string& plaintextStr) const {
	int rc;

	gnutls_datum_t plaintext;
	plaintext.data = reinterpret_cast<unsigned char*>(const_cast<char*>(plaintextStr.c_str()));
	plaintext.size = static_cast<unsigned int>(plaintextStr.size());

	gnutls_datum_t ciphertext;

	rc = gnutls_pubkey_encrypt_data(publicKey, 0, &plaintext, &ciphertext);
	if(rc < 0) {
		throw std::runtime_error("Error gnutls_pubkey_encrypt_data: " + std::string(gnutls_strerror (rc)));
	}

	std::string ciphertextStr(reinterpret_cast<char*>(ciphertext.data), ciphertext.size);
	gnutls_free(ciphertext.data);

	return ciphertextStr;
}

bool PublicKey::verifySignature(const std::string& dataStr, const std::string& signatureStr, const std::string& algorithmStr) const {
	int rc;

	gnutls_datum_t data;
	data.data = reinterpret_cast<unsigned char*>(const_cast<char*>(dataStr.c_str()));
	data.size = static_cast<unsigned int>(dataStr.size());

	gnutls_sign_algorithm_t signAlgorithm = getSignAlgorithm(algorithmStr);
	if(signAlgorithm == GNUTLS_SIGN_UNKNOWN) {
		throw std::runtime_error("Unknown sign algorithm \"" + algorithmStr + "\"");
	}

	//logger.debug << "using sign algorithm \"" << algorithmStr << "\"\n.";
#if 1
	gnutls_datum_t signature;
	signature.data = reinterpret_cast<unsigned char*>(const_cast<char*>(signatureStr.c_str()));
	signature.size = static_cast<unsigned int>(signatureStr.size());

	rc = gnutls_pubkey_verify_data2(publicKey, signAlgorithm, 0, &data, &signature);
#else
	gnutls_datum_t signature;
	if(algorithmStr == "ES256" || algorithmStr == "ES384" || algorithmStr == "ES512") {
		gnutls_datum_t r;
		gnutls_datum_t s;

		if(signatureStr.size() == 64) {
			r.data = reinterpret_cast<unsigned char*>(const_cast<char*>(signatureStr.c_str()));
			r.size = 32;

			s.data = r.data + r.size;
			s.size = r.size;
		}
		else if(signatureStr.size() == 96) {
			r.data = reinterpret_cast<unsigned char*>(const_cast<char*>(signatureStr.c_str()));
			r.size = 48;

			s.data = r.data + r.size;
			s.size = r.size;
		}
		else if(signatureStr.size() == 132) {
			r.data = reinterpret_cast<unsigned char*>(const_cast<char*>(signatureStr.c_str()));
			r.size = 66;

			s.data = r.data + r.size;
			s.size = r.size;
		}
		else {
			throw std::runtime_error("Invalid signature size " + std::to_string(signatureStr.size()) + " for algorithm \"" + algorithmStr + "\"");
		}

		rc = gnutls_encode_rs_value(&signature, &r, &s);
		if(rc != 0) {
			throw std::runtime_error("Error gnutls_encode_rs_value: " + std::string(gnutls_strerror(rc)));
		}

		rc = gnutls_pubkey_verify_data2(pubkey, signAlgorithm, 0, &data, &signature);
		gnutls_free(signature.data);
	}
	else {
		signature.data = reinterpret_cast<unsigned char*>(const_cast<char*>(signatureStr.c_str()));
		signature.size = static_cast<unsigned int>(signatureStr.size());

		rc = gnutls_pubkey_verify_data2(pubkey, signAlgorithm, 0, &data, &signature);
	}
#endif

	return (rc >= 0);
}

PublicKey::PublicKey(gnutls_pubkey_t aPublicKey)
: publicKey(aPublicKey)
{
}

PublicKey::PublicKey(std::unique_ptr<gnutls_pcert_st> aCertificate)
: publicKey(aCertificate->pubkey),
  certificate(std::move(aCertificate))
{
}

gnutls_pubkey_t PublicKey::getPublicKey() const {
	return publicKey;
}

std::unique_ptr<PublicKey> PublicKey::createX509_PUBLIC_KEY(const std::string& publicKeyStr, gnutls_x509_crt_fmt_t encoding) {
	int rc;

	gnutls_datum_t publicKeyDatum;
	publicKeyDatum.data = reinterpret_cast<unsigned char*>(const_cast<char*>(publicKeyStr.c_str()));
	publicKeyDatum.size = static_cast<unsigned int>(publicKeyStr.size());

	gnutls_pubkey_t publicKey = nullptr;
	rc = gnutls_pubkey_init(&publicKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pubkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_pubkey_import(publicKey, &publicKeyDatum, encoding);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(publicKey);
		throw std::runtime_error("Error gnutls_pubkey_import: " + std::string(gnutls_strerror(rc)));
	}

	gnutls_pk_algorithm_t algorithm = static_cast<gnutls_pk_algorithm_t>(gnutls_pubkey_get_pk_algorithm(publicKey, NULL));
	switch(algorithm) {
	case GNUTLS_PK_RSA:
		return std::unique_ptr<PublicKey>(new rsa::PublicKey(publicKey));
	case GNUTLS_PK_EC:
		return std::unique_ptr<PublicKey>(new ec::PublicKey(publicKey));
	default:
		break;
	}

	return std::unique_ptr<PublicKey>(new PublicKey(publicKey));
}

std::unique_ptr<PublicKey> PublicKey::createX509_CERTIFICATE(const std::string& certificateStr, gnutls_x509_crt_fmt_t encoding) {
	int rc;

	gnutls_datum_t certificateDatum;
	certificateDatum.data = reinterpret_cast<unsigned char*>(const_cast<char*>(certificateStr.c_str()));
	certificateDatum.size = static_cast<unsigned int>(certificateStr.size());

	std::unique_ptr<gnutls_pcert_st> certificate(new gnutls_pcert_st);
	/*
		typedef struct gnutls_pcert_st
		{
		  gnutls_pubkey_t pubkey;
		  gnutls_datum_t cert;
		  gnutls_certificate_type_t type;
		} gnutls_pcert_st;
	 */
	rc = gnutls_pcert_import_x509_raw(certificate.get(), &certificateDatum, encoding, 0);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pcert_import_x509_raw: " + std::string(gnutls_strerror (rc)));
	}

	gnutls_pk_algorithm_t algorithm = static_cast<gnutls_pk_algorithm_t>(gnutls_pubkey_get_pk_algorithm(certificate->pubkey, NULL));
	switch(algorithm) {
	case GNUTLS_PK_RSA:
		return std::unique_ptr<PublicKey>(new rsa::PublicKey(std::move(certificate)));
	case GNUTLS_PK_EC:
		return std::unique_ptr<PublicKey>(new ec::PublicKey(std::move(certificate)));
	default:
		break;
	}

	return std::unique_ptr<PublicKey>(new PublicKey(std::move(certificate)));
}

std::string PublicKey::getX509_PUBLIC_KEY(gnutls_x509_crt_fmt_t encoding) const {
	int rc;

#if 1
	gnutls_datum_t x509Datum;
	rc = gnutls_pubkey_export2(publicKey, encoding, &x509Datum);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pubkey_export2: " + std::string(gnutls_strerror(rc)));
	}

	std::string publicKeyStr(reinterpret_cast<char*>(x509Datum.data), x509Datum.size);
	gnutls_free(x509Datum.data);

	return publicKeyStr;
#else
	static char sentinal;
	std::size_t bufferSize = 0;
	rc = gnutls_pubkey_export(publicKey, encoding, &sentinal, &bufferSize);
	if(rc == GNUTLS_E_SUCCESS) {
		return "";
	}
	if(rc != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		throw std::runtime_error("Error gnutls_pubkey_export: " + std::string(gnutls_strerror (rc)));
	}

	std::vector<char> buffer(bufferSize);
	rc = gnutls_pubkey_export(publicKey, encoding, &buffer[0], &bufferSize);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pubkey_export: " + std::string(gnutls_strerror (rc)));
	}

	return std::string(&buffer[0], bufferSize);
#endif
}


} /* namespace gtx */
