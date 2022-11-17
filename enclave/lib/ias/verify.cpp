#include "lib/ias/verify.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

bool THROW_OR_WARN(CoreStatusCode code, std::string message)
{
#ifdef NDEBUG
    THROW_EXCEPTION(code, message);
#else
    WARNING_LOG("%i %s", code, message.c_str());
    return false;
#endif
}

bool verify_signature(const std::string &cert_chain_string,
                      const std::string &content,
                      const std::array<uint8_t, CORE_IAS_SIG_LEN> &signature)
{
    const std::string cert_chain = url_decode(cert_chain_string);

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int ret = mbedtls_x509_crt_parse(
        &chain, reinterpret_cast<const unsigned char *>(cert_chain.c_str()), cert_chain.size() + 1);

    if (ret != 0)
        THROW_EXCEPTION(kClientCertificateParseError, "Parsing the IAS certificate chain failed");

    const std::string root_cert = ias_root_ca_cert;
    mbedtls_x509_crt root;
    mbedtls_x509_crt_init(&root);
    ret = mbedtls_x509_crt_parse(
        &root, reinterpret_cast<const unsigned char *>(root_cert.c_str()), root_cert.size() + 1);
    if (ret != 0)
        THROW_EXCEPTION(kClientCertificateParseError, "Parsing the root IAS certificate failed");

    uint32_t flags;
    ret = mbedtls_x509_crt_verify(&chain, &root, NULL, NULL, &flags, NULL, NULL);
    if (ret != 0 || flags != 0)
        return THROW_OR_WARN(kIASFailed, "Verifying the IAS certificate chain failed");

    // The report body is SHA256 signed with the private key of the
    // signing cert.  Extract the public key from the certificate and
    // verify the signature.
    mbedtls_pk_context pkey = chain.pk;
    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t *md = static_cast<uint8_t *>(malloc(mdinfo->size));
    mbedtls_md(mdinfo, reinterpret_cast<const uint8_t *>(content.data()), content.size(), md);
    ret = mbedtls_pk_verify(
        &pkey, mdinfo->type, md, mdinfo->size, signature.data(), signature.size());

    mbedtls_x509_crt_free(&chain);
    mbedtls_x509_crt_free(&root);
    free(md);

    if (ret != 0)
    {
        return THROW_OR_WARN(kIASFailed, "Signature not valid");
    }

    DEBUG_LOG("IAS signature verification ok!");
    return true;
}

bool verify_quote(const std::string &peer_ias_report_body,
                  const std::array<uint8_t, CORE_ECC_KEY_LEN> &peer_provision_public_key,
                  const std::array<uint8_t, CORE_ED25519_KEY_LEN> &peer_ed25519_signing_public_key,
                  const sgx_report_t &verifier_report)
{
    // Extract the quote from the IAS report body
    const JSON data = JSON::Load(peer_ias_report_body);
    const std::string quote_base64 = data.get("isvEnclaveQuoteBody").String();
    const std::string quote_bytes = b64_decode(quote_base64);
    const sgx_quote_t *quote = reinterpret_cast<const sgx_quote_t *>(quote_bytes.data());

    // Verify that the hash of the input public keys matches that in the report body
    const std::array<uint8_t, CORE_SHA_256_LEN> hash =
        get_public_keys_hash(peer_provision_public_key, peer_ed25519_signing_public_key);

    if (memcmp(hash.data(), &quote->report_body.report_data.d, CORE_SHA_256_LEN) != 0)
        THROW_EXCEPTION(kIASFailed, "Hash of public keys does not match report");

    // Verify the report version
    const auto version = data.get("version").Int();
    if (version != 4)
        return THROW_OR_WARN(kIASFailed, "IAS report version is not 4");

    // Check that the warnings about the enclave are known and acceptable
    const std::string quote_status = data.get("isvEnclaveQuoteStatus").String();
    if (quote_status != "OK")
    {
        const bool sw_hardening_needed = quote_status == "SW_HARDENING_NEEDED";
        const bool lvi = data.hasKey("advisoryIDs") && data.get("advisoryIDs").length() == 1 &&
                         data.get("advisoryIDs").at(0).ToString() == "INTEL-SA-00334";
        if (!(sw_hardening_needed && lvi))
            return THROW_OR_WARN(kIASFailed, "Enclave not on trusted hardware");
    }

    // Verify that the enclave isn't running in debug mode
    if ((quote->report_body.attributes.flags & SGX_FLAGS_DEBUG) == SGX_FLAGS_DEBUG)
        return THROW_OR_WARN(kIASFailed, "Enclave in debug mode");

    // Verify that the MRSIGNER of the peer enclave matches the verifier enclave
    const sgx_measurement_t peer_mr_signer = quote->report_body.mr_signer;
    const sgx_measurement_t verifier_mr_signer = verifier_report.body.mr_signer;
    if (memcmp(peer_mr_signer.m, verifier_mr_signer.m, CORE_MRSIGNER_LEN) != 0)
        THROW_EXCEPTION(kIASFailed, "MRSIGNER of peer enclave doesn't match that of verifier");

    // Verify that the MRSIGNER matches the expected value
    const std::string mrsigner =
        hex_decode("463be517c1f292e2cf5a328d865f03e7cbcc4355e201484c39fedbd55534e849");
    if (memcmp(mrsigner.data(), peer_mr_signer.m, CORE_MRSIGNER_LEN) != 0)
        return THROW_OR_WARN(kIASFailed, "MRSIGNER not allowed");

    // Verify that the MRENCLAVE of the peer enclave matches the verifier enclave
    const sgx_measurement_t peer_mr_enclave = quote->report_body.mr_enclave;
    const sgx_measurement_t verifier_mr_enclave = verifier_report.body.mr_enclave;
    if (memcmp(peer_mr_enclave.m, verifier_mr_enclave.m, CORE_MRENCLAVE_LEN) != 0)
        THROW_EXCEPTION(kIASFailed, "MRENCLAVE of peer enclave doesn't match that of verifier");

    DEBUG_LOG("Enclave quote is valid");
    return true;
}

} // namespace enclave
} // namespace silentdata
