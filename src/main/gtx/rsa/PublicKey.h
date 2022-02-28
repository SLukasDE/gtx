#ifndef GTX_RSA_PUBLICKEY_H_
#define GTX_RSA_PUBLICKEY_H_

#include <gtx/PublicKey.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <string>
#include <memory>

namespace gtx {
namespace rsa {

class PublicKey : public gtx::PublicKey {
friend class gtx::PublicKey;
public:
	static std::unique_ptr<PublicKey> create(const std::string& exponent, const std::string& modulus);

	const std::string& getModulus() const;
	const std::string& getExponent() const;

private:
	struct Parameters {
		std::string modulus;
		std::string exponent;
	};
	mutable std::unique_ptr<Parameters> parameters;

	using gtx::PublicKey::PublicKey;

	const Parameters& getParameters() const;
};

} /* namespace rsa */
} /* namespace gtx */

#endif /* GTX_RSA_PUBLICKEY_H_ */
