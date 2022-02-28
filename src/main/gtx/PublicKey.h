#ifndef GTX_PUBLICKEY_H_
#define GTX_PUBLICKEY_H_

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <string>
#include <memory>

namespace gtx {

class PublicKey {
friend class PrivateKey;
public:
	virtual ~PublicKey();

	static std::unique_ptr<PublicKey> createX509_PUBLIC_KEY_DER(const std::string& publicKey);
	static std::unique_ptr<PublicKey> createX509_PUBLIC_KEY_PEM(const std::string& publicKey);
	static std::unique_ptr<PublicKey> createX509_CERTIFICATE_DER(const std::string& certificate);
	static std::unique_ptr<PublicKey> createX509_CERTIFICATE_PEM(const std::string& certificate);

	static std::unique_ptr<PublicKey> createEC(gnutls_ecc_curve_t curveType, const std::string& coordinateX, const std::string& coordinateY);

	static std::unique_ptr<PublicKey> createRSA(const std::string& exponent, const std::string& modulus);

	std::string getX509_PUBLIC_KEY_DER() const;
	std::string getX509_PUBLIC_KEY_PEM() const;

	std::string getAlgorithmName() const;
	unsigned int getAlgorithmBits() const;
	std::string getPrettyPrint(bool b = true) const;

	std::string encrypt(const std::string& plaintext) const;
	bool verifySignature(const std::string& data, const std::string& signature, const std::string& algorithm = "RS512") const;

protected:
	PublicKey(gnutls_pubkey_t publicKey);
	PublicKey(std::unique_ptr<gnutls_pcert_st> certificate);

	gnutls_pubkey_t getPublicKey() const;

private:
	gnutls_pubkey_t publicKey = nullptr;
	std::unique_ptr<gnutls_pcert_st> certificate;

	static std::unique_ptr<PublicKey> createX509_PUBLIC_KEY(const std::string& publicKey, gnutls_x509_crt_fmt_t encoding);
	static std::unique_ptr<PublicKey> createX509_CERTIFICATE(const std::string& certificate, gnutls_x509_crt_fmt_t encoding);
	std::string getX509_PUBLIC_KEY(gnutls_x509_crt_fmt_t encoding) const;
};

} /* namespace gtx */

#endif /* GTX_PUBLICKEY_H_ */
