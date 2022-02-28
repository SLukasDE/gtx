#include <gtx/ec/PrivateKey.h>

#include <gnutls/abstract.h>

#include <stdexcept>

namespace gtx {
namespace ec {

namespace {
gnutls_x509_privkey_t getPrivateKeyX509(gnutls_privkey_t privateKey) {
	gnutls_x509_privkey_t privateKeyX509;

	int rc;
	// This function is missing: rc = gnutls_privkey_export_x509(privateKeyX509, &key);

	gnutls_ecc_curve_t curveType;
	gnutls_datum_t curveKey;
	gnutls_datum_t coordinateX;
	gnutls_datum_t coordinateY;

	rc = gnutls_privkey_export_ecc_raw(privateKey, &curveType, &coordinateX, &coordinateY, &curveKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_privkey_export_ecc_raw: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_x509_privkey_init(&privateKeyX509);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_free(curveKey.data);
		gnutls_free(coordinateX.data);
		gnutls_free(coordinateY.data);

		throw std::runtime_error("Error gnutls_x509_privkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_x509_privkey_import_ecc_raw (privateKeyX509, curveType, &coordinateX, &coordinateY, &curveKey);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(privateKeyX509);

		gnutls_free(curveKey.data);
		gnutls_free(coordinateX.data);
		gnutls_free(coordinateY.data);

		throw std::runtime_error("Error gnutls_x509_privkey_import_ecc_raw: " + std::string(gnutls_strerror(rc)));
	}

	gnutls_free(curveKey.data);
	gnutls_free(coordinateX.data);
	gnutls_free(coordinateY.data);

	return privateKeyX509;
}
} /* anonymous namespace */

std::unique_ptr<PrivateKey> PrivateKey::create(gnutls_ecc_curve_t curveType, const std::string& curveKeyStr, const std::string& coordinateXStr, const std::string& coordinateYStr) {
	int rc;

	gnutls_datum_t curveKey;
	curveKey.data = reinterpret_cast<unsigned char*>(const_cast<char*>(curveKeyStr.c_str()));
	curveKey.size = static_cast<unsigned int>(curveKeyStr.size());

	gnutls_datum_t coordinateX;
	coordinateX.data = reinterpret_cast<unsigned char*>(const_cast<char*>(coordinateXStr.c_str()));
	coordinateX.size = static_cast<unsigned int>(coordinateXStr.size());

	gnutls_datum_t coordinateY;
	coordinateY.data = reinterpret_cast<unsigned char*>(const_cast<char*>(coordinateYStr.c_str()));
	coordinateY.size = static_cast<unsigned int>(coordinateYStr.size());

	gnutls_privkey_t privateKey = nullptr;
	rc = gnutls_privkey_init(&privateKey);
	if(rc != GNUTLS_E_SUCCESS) {
		throw std::runtime_error("Error gnutls_privkey_init: " + std::string(gnutls_strerror(rc)));
	}

	rc = gnutls_privkey_import_ecc_raw(privateKey, curveType, &coordinateX, &coordinateY, &curveKey);
	if(rc != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(privateKey);
		throw std::runtime_error("Error gnutls_privkey_import_ecc_raw: " + std::string(gnutls_strerror (rc)));
	}

	return std::unique_ptr<PrivateKey>(new PrivateKey(privateKey, getPrivateKeyX509(privateKey)));
}

gnutls_ecc_curve_t PrivateKey::getCurveType() const {
	return getParameters().curveType;
}

const std::string& PrivateKey::getCurveKey() const {
	return getParameters().curveKey;
}

const std::string& PrivateKey::getCoordinateX() const {
	return getParameters().coordinateX;
}

const std::string& PrivateKey::getCoordinateY() const {
	return getParameters().coordinateY;
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
		gnutls_ecc_curve_t curveType;
		gnutls_datum_t curveKey;
		gnutls_datum_t coordinateX;
		gnutls_datum_t coordinateY;

		rc = gnutls_privkey_export_ecc_raw(getPrivateKey(), &curveType, &coordinateX, &coordinateY, &curveKey);
		if(rc != GNUTLS_E_SUCCESS) {
			throw std::runtime_error("Error gnutls_privkey_export_ecc_raw: " + std::string(gnutls_strerror(rc)));
		}

		parameters.reset(new Parameters);

		parameters->curveType = curveType;

		parameters->curveKey = std::string(reinterpret_cast<char*>(curveKey.data), curveKey.size);
		gnutls_free(curveKey.data);

		parameters->coordinateX = std::string(reinterpret_cast<char*>(coordinateX.data), coordinateX.size);
		gnutls_free(coordinateX.data);

		parameters->coordinateY = std::string(reinterpret_cast<char*>(coordinateY.data), coordinateY.size);
		gnutls_free(coordinateY.data);
	}

	return *parameters;
}

} /* namespace ec */
} /* namespace gtx */
