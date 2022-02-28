#include <gtx/ec/PublicKey.h>

#include <stdexcept>

namespace gtx {
namespace ec {

std::unique_ptr<PublicKey> PublicKey::create(gnutls_ecc_curve_t curveType, const std::string& coordinateXStr, const std::string& coordinateYStr) {
	int rc;

	gnutls_datum_t coordinateX;
	coordinateX.data = reinterpret_cast<unsigned char*>(const_cast<char*>(coordinateXStr.c_str()));
	coordinateX.size = static_cast<unsigned int>(coordinateXStr.size());

	gnutls_datum_t coordinateY;
	coordinateY.data = reinterpret_cast<unsigned char*>(const_cast<char*>(coordinateYStr.c_str()));
	coordinateY.size = static_cast<unsigned int>(coordinateYStr.size());

	gnutls_pubkey_t publicKey = nullptr;
	rc = gnutls_pubkey_init(&publicKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_pubkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_pubkey_import_ecc_raw(publicKey, curveType, &coordinateX, &coordinateY);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(publicKey);
		throw std::runtime_error("Error gnutls_pubkey_import_ecc_raw: " + std::string(gnutls_strerror (rc)));
	}

	return std::unique_ptr<PublicKey>(new PublicKey(publicKey));
}

gnutls_ecc_curve_t PublicKey::getCurveType() const {
	return getParameters().curveType;
}

const std::string& PublicKey::getCoordinateX() const {
	return getParameters().coordinateX;
}

const std::string& PublicKey::getCoordinateY() const {
	return getParameters().coordinateY;
}

const PublicKey::Parameters& PublicKey::getParameters() const {
	if(!parameters) {
		int rc;
		gnutls_ecc_curve_t curveType;
		gnutls_datum_t coordinateX;
		gnutls_datum_t coordinateY;

		rc = gnutls_pubkey_export_ecc_raw(getPublicKey(), &curveType, &coordinateX, &coordinateY);
		if(rc != GNUTLS_E_SUCCESS) {
			throw std::runtime_error("Error gnutls_pubkey_export_ecc_raw: " + std::string(gnutls_strerror(rc)));
		}

		parameters.reset(new Parameters);

		parameters->curveType = curveType;

		parameters->coordinateX = std::string(reinterpret_cast<char*>(coordinateX.data), coordinateX.size);
		gnutls_free(coordinateX.data);

		parameters->coordinateY = std::string(reinterpret_cast<char*>(coordinateY.data), coordinateY.size);
		gnutls_free(coordinateY.data);
	}

	return *parameters;
}

} /* namespace ec */
} /* namespace gtx */
