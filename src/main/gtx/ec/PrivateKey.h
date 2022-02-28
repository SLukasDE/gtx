#ifndef GTX_EC_PRIVATEKEY_H_
#define GTX_EC_PRIVATEKEY_H_

#include <gtx/PrivateKey.h>

#include <gnutls/gnutls.h>

#include <string>
#include <memory>

namespace gtx {
namespace ec {

class PrivateKey : public gtx::PrivateKey {
friend class gtx::PrivateKey;
public:
	static std::unique_ptr<PrivateKey> create(gnutls_ecc_curve_t curveType, const std::string& curveKey, const std::string& coordinateX, const std::string& coordinateY);

	gnutls_ecc_curve_t getCurveType() const;
	const std::string& getCurveKey() const;
	const std::string& getCoordinateX() const;
	const std::string& getCoordinateY() const;

private:
	struct Parameters {
		gnutls_ecc_curve_t curveType = GNUTLS_ECC_CURVE_INVALID;
		std::string curveKey;
		std::string coordinateX;
		std::string coordinateY;
	};
	mutable std::unique_ptr<Parameters> parameters;

	//PrivateKey(gnutls_privkey_t privateKey, gnutls_x509_privkey_t privateKeyX509);
	using gtx::PrivateKey::PrivateKey;

	const Parameters& getParameters() const;
};

} /* namespace ec */
} /* namespace gtx */

#endif /* GTX_EC_PRIVATEKEY_H_ */
