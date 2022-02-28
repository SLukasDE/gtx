#include <gtx/rsa/PrivateKey.h>

#include <gnutls/abstract.h>

#include <stdexcept>

namespace gtx {
namespace rsa {

namespace {
gnutls_x509_privkey_t getPrivateKeyX509(gnutls_privkey_t privateKey) {
	int rc;
	gnutls_x509_privkey_t privateKeyX509;
	// This function is missing: rc = gnutls_privkey_export_x509(privateKeyX509, &key);

	//gnutls_pkcs11_privkey_t pkcs11_key;
	//rc = gnutls_privkey_export_pkcs11 (privateKey, &pkcs11_key);

	gnutls_datum_t modulus;
	gnutls_datum_t exponent;
	gnutls_datum_t d;
	gnutls_datum_t p;
	gnutls_datum_t q;
	gnutls_datum_t u;
	gnutls_datum_t e1;
	gnutls_datum_t e2;

	rc = gnutls_privkey_export_rsa_raw(privateKey, &modulus, &exponent, &d, &p, &q, &u, &e1, &e2);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_privkey_export_rsa_raw: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_x509_privkey_init(&privateKeyX509);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_free(modulus.data);
		gnutls_free(exponent.data);
		gnutls_free(d.data);
		gnutls_free(p.data);
		gnutls_free(q.data);
		gnutls_free(u.data);
		gnutls_free(e1.data);
		gnutls_free(e2.data);

		throw std::runtime_error("Error gnutls_x509_privkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_x509_privkey_import_rsa_raw2(privateKeyX509, &modulus, &exponent, &d, &p, &q, &u, &e1, &e2);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(privateKeyX509);

		gnutls_free(modulus.data);
		gnutls_free(exponent.data);
		gnutls_free(d.data);
		gnutls_free(p.data);
		gnutls_free(q.data);
		gnutls_free(u.data);
		gnutls_free(e1.data);
		gnutls_free(e2.data);

		throw std::runtime_error("Error gnutls_x509_privkey_import_rsa_raw2: " + std::string(gnutls_strerror(rc)));
	}

	gnutls_free(modulus.data);
	gnutls_free(exponent.data);
	gnutls_free(d.data);
	gnutls_free(p.data);
	gnutls_free(q.data);
	gnutls_free(u.data);
	gnutls_free(e1.data);
	gnutls_free(e2.data);

	return privateKeyX509;
}
} /* anonymous namespace */

std::unique_ptr<PrivateKey> PrivateKey::create(const std::string& publicExponentStr, const std::string& privateExponentStr, const std::string& modulusStr, const std::string& primePStr, const std::string& primeQStr, const std::string& coefficientStr) {
	int rc;

	gnutls_x509_privkey_t privateKeyX509 = nullptr;
	if(gnutls_x509_privkey_init(&privateKeyX509)) {
		throw std::runtime_error("Error gnutls_x509_privkey_init: no memory");
	}

	gnutls_datum_t publicExponent;
	publicExponent.data = reinterpret_cast<unsigned char*>(const_cast<char*>(publicExponentStr.c_str()));
	publicExponent.size = static_cast<unsigned int>(publicExponentStr.size());

	gnutls_datum_t privateExponent;
	privateExponent.data = reinterpret_cast<unsigned char*>(const_cast<char*>(privateExponentStr.c_str()));
	privateExponent.size = static_cast<unsigned int>(privateExponentStr.size());

	gnutls_datum_t modulus;
	modulus.data = reinterpret_cast<unsigned char*>(const_cast<char*>(modulusStr.c_str()));
	modulus.size = static_cast<unsigned int>(modulusStr.size());

	gnutls_datum_t primeP;
	primeP.data = reinterpret_cast<unsigned char*>(const_cast<char*>(primePStr.c_str()));
	primeP.size = static_cast<unsigned int>(primePStr.size());

	gnutls_datum_t primeQ;
	primeQ.data = reinterpret_cast<unsigned char*>(const_cast<char*>(primeQStr.c_str()));
	primeQ.size = static_cast<unsigned int>(primeQStr.size());

	gnutls_datum_t coefficient;
	coefficient.data = reinterpret_cast<unsigned char*>(const_cast<char*>(coefficientStr.c_str()));
	coefficient.size = static_cast<unsigned int>(coefficientStr.size());

	rc = gnutls_x509_privkey_import_rsa_raw (privateKeyX509, &modulus, &publicExponent, &privateExponent, &primeP, &primeQ, &coefficient);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(privateKeyX509);
		throw std::runtime_error("Error gnutls_x509_privkey_import_rsa_raw: " + std::string(gnutls_strerror(rc)));
	}

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

	return std::unique_ptr<PrivateKey>(new PrivateKey(privateKey, privateKeyX509));
}

std::unique_ptr<PrivateKey> PrivateKey::create(unsigned int bits) {
	int rc;

	gnutls_privkey_t privateKey = nullptr;
	rc = gnutls_privkey_init(&privateKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_privkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_privkey_generate(privateKey, GNUTLS_PK_RSA, bits, 0);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(privateKey);
		throw std::runtime_error("Error gnutls_privkey_generate: " + std::string(gnutls_strerror (rc)));
	}

	return std::unique_ptr<PrivateKey>(new PrivateKey(privateKey, getPrivateKeyX509(privateKey)));
}

const std::string& PrivateKey::getModulus() const {
	return getParameters().modulus;
}

const std::string& PrivateKey::getPublicExponent() const {
	return getParameters().publicExponent;
}

const std::string& PrivateKey::getPrivateExponent() const {
	return getParameters().privateExponent;
}

const std::string& PrivateKey::getPrimeP() const {
	return getParameters().primeP;
}

const std::string& PrivateKey::getPrimeQ() const {
	return getParameters().primeQ;
}

const std::string& PrivateKey::getCoefficient() const {
	return getParameters().coefficient;
}

const std::string& PrivateKey::getE1() const {
	return getParameters().e1;
}

const std::string& PrivateKey::getE2() const {
	return getParameters().e2;
}
/*
PrivateKey::PrivateKey(gnutls_privkey_t aPrivateKey, gnutls_x509_privkey_t aPrivateKeyX509)
: gtx::PrivateKey(aPrivateKey, aPrivateKeyX509)
{
}
*/
const PrivateKey::Parameters& PrivateKey::getParameters() const {
	if(!parameters) {
		int rc;
		gnutls_datum_t modulus;
		gnutls_datum_t publicExponent;
		gnutls_datum_t privateExponent;
		gnutls_datum_t primeP;
		gnutls_datum_t primeQ;
		gnutls_datum_t coefficient;
		gnutls_datum_t e1;
		gnutls_datum_t e2;

		/* do not extract anything we don't need */
		rc = gnutls_privkey_export_rsa_raw(getPrivateKey(), &modulus, &publicExponent, &privateExponent, &primeP, &primeQ, &coefficient, &e1, &e2);
		if(rc != GNUTLS_E_SUCCESS) {
			throw std::runtime_error("Error gnutls_privkey_export_rsa_raw: " + std::string(gnutls_strerror(rc)));
		}

		parameters.reset(new Parameters);

		parameters->modulus = std::string(reinterpret_cast<char*>(modulus.data), modulus.size);
		gnutls_free(modulus.data);

		parameters->publicExponent = std::string(reinterpret_cast<char*>(publicExponent.data), publicExponent.size);
		gnutls_free(publicExponent.data);

		parameters->privateExponent = std::string(reinterpret_cast<char*>(privateExponent.data), privateExponent.size);
		gnutls_free(privateExponent.data);

		parameters->primeP = std::string(reinterpret_cast<char*>(primeP.data), primeP.size);
		gnutls_free(primeP.data);

		parameters->primeQ = std::string(reinterpret_cast<char*>(primeQ.data), primeQ.size);
		gnutls_free(primeQ.data);

		parameters->coefficient = std::string(reinterpret_cast<char*>(coefficient.data), coefficient.size);
		gnutls_free(coefficient.data);

		parameters->e1 = std::string(reinterpret_cast<char*>(e1.data), e1.size);
		gnutls_free(e1.data);

		parameters->e2 = std::string(reinterpret_cast<char*>(e2.data), e2.size);
		gnutls_free(e2.data);
	}

	return *parameters;
}

} /* namespace rsa */
} /* namespace gtx */
