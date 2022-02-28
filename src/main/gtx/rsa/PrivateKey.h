#ifndef GTX_RSA_PRIVATEKEY_H_
#define GTX_RSA_PRIVATEKEY_H_

#include <gtx/PrivateKey.h>

#include <gnutls/gnutls.h>

#include <string>
#include <memory>

namespace gtx {
namespace rsa {

class PrivateKey : public gtx::PrivateKey {
friend class gtx::PrivateKey;
public:
	static std::unique_ptr<PrivateKey> create(const std::string& publicExponent, const std::string& privateExponent, const std::string& modulus, const std::string& primeP, const std::string& primeQ, const std::string& coefficient);
	static std::unique_ptr<PrivateKey> create(unsigned int bits = 4096);

	const std::string& getModulus() const;
	const std::string& getPublicExponent() const;
	const std::string& getPrivateExponent() const;
	const std::string& getPrimeP() const;
	const std::string& getPrimeQ() const;
	const std::string& getCoefficient() const;
	const std::string& getE1() const;
	const std::string& getE2() const;

private:
	struct Parameters {
		std::string modulus;
		std::string publicExponent;
		std::string privateExponent;
		std::string primeP;
		std::string primeQ;
		std::string coefficient;
		std::string e1;
		std::string e2;
	};
	mutable std::unique_ptr<Parameters> parameters;

	using gtx::PrivateKey::PrivateKey;
	//PrivateKey(gnutls_privkey_t privateKey, gnutls_x509_privkey_t privateKeyX509);

	const Parameters& getParameters() const;
};

} /* namespace rsa */
} /* namespace gtx */

#endif /* GTX_RSA_PRIVATEKEY_H_ */
