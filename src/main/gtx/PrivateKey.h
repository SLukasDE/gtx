#ifndef GTX_PRIVATEKEY_H_
#define GTX_PRIVATEKEY_H_

#include <gnutls/gnutls.h>

#include <string>
#include <memory>

namespace gtx {
class PublicKey;

class PrivateKey {
public:
	virtual ~PrivateKey();

	static std::unique_ptr<PrivateKey> createX509_DER(const std::string& privateKey, const std::string& password = "");
	static std::unique_ptr<PrivateKey> createX509_PEM(const std::string& privateKey, const std::string& password = "");

	static std::unique_ptr<PrivateKey> createEC(gnutls_ecc_curve_t curveType, const std::string& curveKey, const std::string& coordinateX, const std::string& coordinateY);

	static std::unique_ptr<PrivateKey> createRSA(const std::string& publicExponent, const std::string& privateExponent, const std::string& modulus, const std::string& primeP, const std::string& primeQ, const std::string& coefficient);
	static std::unique_ptr<PrivateKey> createRSA(unsigned int bits = 4096);

	std::string getX509_PRIVATE_KEY_DER(const std::string& password) const;
	std::string getX509_PRIVATE_KEY_PEM(const std::string& password) const;

	std::unique_ptr<PublicKey> createPublicKey();

	std::string getAlgorithmName() const;
	unsigned int getAlgorithmBits() const;

	std::string decrypt(const std::string& ciphertextStr) const;
	std::string sign(const std::string& data, const std::string& algorithm = "RS512") const;

protected:
	PrivateKey(gnutls_privkey_t privateKey, gnutls_x509_privkey_t privateKeyX509);

	gnutls_privkey_t getPrivateKey() const;

private:
	gnutls_privkey_t privateKey = nullptr;
	gnutls_x509_privkey_t privateKeyX509 = nullptr;

	static std::unique_ptr<PrivateKey> createX509(const std::string& privateKey, const std::string& password, gnutls_x509_crt_fmt_t encoding);
	std::string getX509_PRIVATE_KEY(const std::string& passwordStr, gnutls_x509_crt_fmt_t encoding) const;
};

} /* namespace gtx */

#endif /* GTX_PRIVATEKEY_H_ */
