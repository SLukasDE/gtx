#ifndef GTX_EC_PUBLICKEY_H_
#define GTX_EC_PUBLICKEY_H_

#include <gtx/PublicKey.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <string>
#include <memory>

namespace gtx {
namespace ec {

class PublicKey : public gtx::PublicKey {
friend class gtx::PublicKey;
public:
	static std::unique_ptr<PublicKey> create(gnutls_ecc_curve_t curveType, const std::string& coordinateX, const std::string& coordinateY);

	gnutls_ecc_curve_t getCurveType() const;
	const std::string& getCoordinateX() const;
	const std::string& getCoordinateY() const;

private:
	struct Parameters {
		gnutls_ecc_curve_t curveType = GNUTLS_ECC_CURVE_INVALID;
		std::string coordinateX;
		std::string coordinateY;
	};

	mutable std::unique_ptr<Parameters> parameters;

	using gtx::PublicKey::PublicKey;

	const Parameters& getParameters() const;
};

} /* namespace ec */
} /* namespace gtx */

#endif /* GTX_EC_PUBLICKEY_H_ */
