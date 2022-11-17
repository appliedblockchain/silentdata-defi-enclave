#include "lib/proof/proof_handlers.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

std::string get_plaid_host(const std::string &environment)
{
#ifdef NDEBUG
    if (environment != "production")
        THROW_EXCEPTION(kInvalidInput,
                        "Plaid API config parameter \"environment\" can not be \"" + environment +
                            "\". Only \"production\" is allowed.");
#endif

    if (environment != "production" && environment != "development" && environment != "sandbox")
        THROW_EXCEPTION(kInvalidInput,
                        "Plaid API config parameter \"environment\" can not be \"" + environment +
                            "\". Only \"production\", \"development\" or \"sandbox\" are allowed.");

    return environment + ".plaid.com";
}

std::string get_truelayer_host(const std::string &environment)
{
#ifdef NDEBUG
    if (environment != "production")
        THROW_EXCEPTION(kInvalidInput,
                        "TrueLayer API config parameter \"environment\" can not be \"" +
                            environment + "\". Only \"production\" is allowed.");
#endif

    if (environment != "production" && environment != "sandbox")
        THROW_EXCEPTION(kInvalidInput,
                        "TrueLayer API config parameter \"environment\" can not be \"" +
                            environment + "\". Only \"production\" or \"sandbox\" are allowed.");

    if (environment == "sandbox")
        return "truelayer-sandbox.com";

    return "truelayer.com";
}

std::unique_ptr<BankClient> create_bank_client(const APIRequest *request)
{
    std::unique_ptr<BankClient> client;

    if (request->get_api_client(0) == "plaid")
    {
        const CBORMap decrypted_data(request->get_decrypted_input(), {"public_token"});
        const std::string public_token = decrypted_data.get("public_token").get_text_string_value();

        // Configure the Plaid options
        const std::string hostname = get_plaid_host(request->get_api_config(0).environment());
        client = std::unique_ptr<BankClient>(
            new PlaidClient(hostname,
                            request->get_api_config(0),
                            public_token,
                            {request->get_allowed_certificate(hostname)}));
    }
    else if (request->get_api_client(0) == "truelayer")
    {
        const CBORMap decrypted_data(request->get_decrypted_input(), {"code", "code_verifier"});

        const std::string code = decrypted_data.get("code").get_text_string_value();
        const std::string code_verifier =
            decrypted_data.get("code_verifier").get_text_string_value();

        // Configure the TrueLayer options
        const std::string hostname = get_truelayer_host(request->get_api_config(0).environment());
        client = std::unique_ptr<BankClient>(
            new TrueLayerClient(hostname,
                                request->get_api_config(0),
                                code,
                                code_verifier,
                                {request->get_allowed_certificate("auth." + hostname),
                                 request->get_allowed_certificate("api." + hostname)}));
    }
    else
    {
        THROW_EXCEPTION(kClientConfigurationError, "Invalid API client option");
    }

    return client;
}

CheckResult process_crossflow_invoice_proof(const CrossflowInvoiceCheckRequestWrapper &request,
                                            const ED25519KeyPair &ed25519_signing_keys)
{
    CheckResult result;
    result.status = kUnknownError;

    // Construct a Crossflow client and request access
    const auto &api_config = request.get_api_config(0);
    CrossflowClient crossflow_client("ts-dev.silentdata.com", api_config.server_timestamp());

    const auto &email = api_config.client_id();
    const auto &password = api_config.secret();
    crossflow_client.get_access(email, password);

    // Get the invoice details from crossflow
    const auto invoice_opt = crossflow_client.get_invoice(request.get_cf_request_id());
    if (!invoice_opt.has_value())
        THROW_EXCEPTION(kInvalidInput,
                        "No invoice returned by Crossflow with specified cf_request_id");

    const auto &invoice = invoice_opt.value();

    // Get the risk score as a uint8_t
    const int risk_score = get_risk_score(invoice.credit_rating);
    if (risk_score < 0)
        THROW_EXCEPTION(kUIntUnderflow,
                        "Risk score obtained is < 0 and so can't be cast to uint8_t");

    if (risk_score > std::numeric_limits<uint8_t>::max())
        THROW_EXCEPTION(kIntegerOverflow,
                        "Risk score obtained is > UNINT8_MAX and so can't be cast to uint8_t");

    // Get the invoice value as a uint64_t (in units of currency_code / 100)
    const double value = std::round(invoice.financeable_total * 100);
    if (value < 0)
        THROW_EXCEPTION(kUIntUnderflow, "Invoice value is negative");
    if (value > CORE_MAX_SAFE_INTEGER)
        THROW_EXCEPTION(kIntegerOverflow, "Invoice amount larger than MAX_SAFE_INTEGER");

    // Set the interest rate (stored as 1000000 * percentage, i.e. at most 6 decimal places)
    uint64_t interest_rate = static_cast<uint64_t>(std::round(1e6 * invoice.interest_rate));

    // Set the invoice ID as a hash of the buyer, buyer_id, and cf_request_id
    if (invoice.buyer.empty())
        THROW_EXCEPTION(kInvalidInput, "Buyer is empty");

    const std::string message =
        invoice.buyer + std::to_string(invoice.buyer_id) + request.get_cf_request_id();
    std::vector<uint8_t> message_bytes(message.size(), 0);
    std::copy(message.begin(), message.end(), message_bytes.begin());

    std::array<uint8_t, CORE_SHA_256_LEN> invoice_id = Hash::get_SHA_256_digest(message_bytes);

    // Set the rest
    int32_t due_date =
        invoice.timestamp + (invoice.tenor * 24 * 60 * 60); // Tenor is days until expiry
    result.binary_proof_data =
        generate_crossflow_invoice_proof_data(request.get_proof_id(),
                                              request.get_server_timestamp(),
                                              invoice.destination_pubkey,
                                              {},
                                              invoice_id,
                                              request.get_minting_app_id(),
                                              static_cast<uint8_t>(risk_score),
                                              static_cast<uint64_t>(value),
                                              invoice.currency,
                                              interest_rate,
                                              invoice.timestamp,
                                              due_date);
    result.signature =
        ed25519_signing_keys.algorand_sign(result.binary_proof_data, request.get_program_hash());
    result.status = kSuccess;

    return result;
}

CheckResult process_balance_proof(const BalanceCheckRequestWrapper &request,
                                  const ED25519KeyPair &ed25519_signing_keys)
{
    CheckResult result;
    result.status = kUnknownError;

    request.verify_wallet_signature();

    std::unique_ptr<BankClient> client = create_bank_client(&request);

    // Access token request
    client->get_access();

    std::string account_id;
    if (request.match_account_numbers())
    {
        const std::map<std::string, AccountNumbers> account_details = client->get_account_details();
        account_id = find_account(account_details, request.get_account_numbers());
    }

    // Account balance request
    const BankBalance balance = client->get_total_balance(request.get_currency_code(), account_id);

    // Do the proof check
    if (!check_minimum_balance(balance, request.get_currency_code(), request.get_minimum_balance()))
    {
        result.status = kMinimumBalanceRequirementsNotMet;
        return result;
    }

    // Access (and public) token destruction request
    client->destroy_access();

    CBORMap certificate_map;
    certificate_map.insert(client->server_address(), client->get_leaf_certificate());
    result.certificate_data = certificate_map.encode_cbor(CORE_MAX_CERTIFICATE_LEN);
    std::vector<uint8_t> certificate_hash = Hash::get_digest(Hash::SHA256, result.certificate_data);

    // Proof data and signature verification
    result.binary_proof_data = generate_bank_proof_data(kMinimumBalanceProof,
                                                        request.get_proof_id(),
                                                        request.get_server_timestamp(),
                                                        request.get_wallet_public_key(),
                                                        certificate_hash,
                                                        request.get_currency_code(),
                                                        request.get_minimum_balance(),
                                                        client->get_timestamp(),
                                                        client->get_api_common_name());

    if (request.get_blockchain() == kAlgorand)
        result.signature = ed25519_signing_keys.algorand_sign(result.binary_proof_data,
                                                              request.get_program_hash());
    else
        result.signature = ed25519_signing_keys.sign(result.binary_proof_data);

    result.status = kSuccess;

    return result;
}

CheckResult process_income_proof(const IncomeCheckRequestWrapper &request,
                                 const ED25519KeyPair &ed25519_signing_keys)
{
    CheckResult result;
    result.status = kUnknownError;

    request.verify_wallet_signature();

    std::unique_ptr<BankClient> client = create_bank_client(&request);

    // Access token request
    client->get_access();

    std::string account_id;
    if (request.match_account_numbers())
    {
        const std::map<std::string, AccountNumbers> account_details = client->get_account_details();
        account_id = find_account(account_details, request.get_account_numbers());
    }

    // The number of months of historical transactions to check
    const int num_months = 3;

    // The number of days of tolerance to use for the stable income check
    const int tolerance_days = 3;

    const auto end_date = http_date_to_tm(client->get_timestamp());
    const auto start_date = subtract_tm_months(end_date, num_months);

    if (request.is_stable())
    {
        // Request transactions from the start_date - 2*tolerance to the end_date
        // Then process the period (start_date - tolerance) to (end_date - tolerance)

        const auto tolerance_sec = tolerance_days * 24 * 60 * 60;
        const auto start_date_with_tolerance =
            timestamp_to_tm(tm_to_timestamp(start_date) - tolerance_sec);
        const auto start_date_with_2_tolerance =
            timestamp_to_tm(tm_to_timestamp(start_date) - 2 * tolerance_sec);
        const auto end_date_with_tolerance =
            timestamp_to_tm(tm_to_timestamp(end_date) - tolerance_sec);
        const std::vector<BankTransaction> transactions =
            client->get_all_transactions(start_date_with_2_tolerance, end_date, account_id);

        // Verify the transactions are stable
        if (!check_stable_income(transactions,
                                 start_date_with_tolerance,
                                 end_date_with_tolerance,
                                 request.get_currency_code(),
                                 tolerance_days,
                                 request.get_consistent_income()))
        {
            WARNING_LOG("Stable income requirements were not met");
            result.status = kConsistentIncomeRequirementsNotMet;
            return result;
        }
    }
    else
    {
        // Get the transactions in the last 3 full months (from the 1st of the month)
        auto start_date_start_of_month = start_date;
        start_date_start_of_month.tm_mday = 1;

        auto end_date_start_of_month = end_date;
        end_date_start_of_month.tm_mday = 1;

        const std::vector<BankTransaction> transactions = client->get_all_transactions(
            start_date_start_of_month, end_date_start_of_month, account_id);

        // Verify the transactions are consistent
        if (!check_consistent_income(transactions,
                                     start_date_start_of_month,
                                     end_date_start_of_month,
                                     request.get_currency_code(),
                                     request.get_consistent_income()))
        {
            WARNING_LOG("Consistent income requirements were not met");
            result.status = kConsistentIncomeRequirementsNotMet;
            return result;
        }
    }

    // Access (and public) token destruction request
    client->destroy_access();

    CBORMap certificate_map;
    certificate_map.insert(client->server_address(), client->get_leaf_certificate());
    result.certificate_data = certificate_map.encode_cbor(CORE_MAX_CERTIFICATE_LEN);
    std::vector<uint8_t> certificate_hash = Hash::get_digest(Hash::SHA256, result.certificate_data);

    ProofType type = kConsistentIncomeProof;
    if (request.is_stable())
        type = kStableIncomeProof;
    result.binary_proof_data = generate_bank_proof_data(type,
                                                        request.get_proof_id(),
                                                        request.get_server_timestamp(),
                                                        request.get_wallet_public_key(),
                                                        certificate_hash,
                                                        request.get_currency_code(),
                                                        request.get_consistent_income(),
                                                        client->get_timestamp(),
                                                        client->get_api_common_name());
    if (request.get_blockchain() == kAlgorand)
        result.signature = ed25519_signing_keys.algorand_sign(result.binary_proof_data,
                                                              request.get_program_hash());
    else
        result.signature = ed25519_signing_keys.sign(result.binary_proof_data);

    result.status = kSuccess;

    return result;
}

void validate_onfido_api_key(const std::string &api_key)
{

    std::vector<std::string> allowed_prefixes({"api_live"});
#ifndef NDEBUG
    allowed_prefixes.push_back("api_sandbox");
#endif

    std::string concatenated_prefixes = "";
    bool has_valid_prefix = false;
    for (const auto &allowed_prefix : allowed_prefixes)
    {
        const auto prefix = api_key.substr(0, allowed_prefix.size());
        if (prefix == allowed_prefix)
        {
            has_valid_prefix = true;
            break;
        }

        concatenated_prefixes +=
            std::string(concatenated_prefixes.empty() ? "" : ", ") + "\"" + allowed_prefix + "\"";
    }

    if (!has_valid_prefix)
        THROW_EXCEPTION(kInvalidInput,
                        "Onfido API key has an invalid prefix. Please use one of: " +
                            concatenated_prefixes);
}

CheckResult process_onfido_kyc_proof(const OnfidoKYCCheckRequestWrapper &request,
                                     const ED25519KeyPair &ed25519_signing_keys)
{
    CheckResult result;
    result.status = kUnknownError;

    request.verify_wallet_signature();

    // The input data is the Onfido applicant ID & the process ID
    const CBORMap decrypted_data(request.get_decrypted_input(),
                                 {"onfido_applicant_id", "process_id"});

    // Extract the applicant ID
    const std::string applicant_id =
        decrypted_data.get("onfido_applicant_id").get_text_string_value();

    // Construct an Onfido client
    const auto &api_config = request.get_api_config(0);
    const auto api_key = api_config.secret();
    validate_onfido_api_key(api_key);
    const std::string &onfido_hostname = "api.eu.onfido.com";
    OnfidoClient onfido_client(onfido_hostname,
                               api_key,
                               api_config.server_timestamp(),
                               {request.get_allowed_certificate(onfido_hostname)});

    // Run the KYC check
    const KYCCheck check_result = onfido_client.verify_applicant_reports(applicant_id);
    if (!check_result.passed)
        THROW_EXCEPTION(kInvalidInput, "Applicant didn't pass Onfido KYC check");

    // Ensure that the timestamp of the checks isn't in the future
    if (check_result.timestamp > api_config.server_timestamp())
        THROW_EXCEPTION(kInvalidInput, "Timestamp from Onfido KYC check is in the future");

    // Ensure that the timestamp of the checks isn't more than 1 day in the past future
    //   ATTN this check is disabled if the API_KEY is for the Onfido sandbox
    //   This is to allow the same applicant ID to be used for tests
    if (api_key.substr(0, 11) != "api_sandbox")
    {
        if (check_result.timestamp < api_config.server_timestamp() - (24 * 60 * 60))
            THROW_EXCEPTION(kInvalidInput,
                            "Timestamp from Onfido KYC check is more than 1 day in the past");
    }

    const SubjectDetails subject_details = onfido_client.fetch_subject_details(applicant_id);

    // Ensure that the subject is at least 18 years old
    if (!check_minimum_age(api_config.server_timestamp(), subject_details.date_of_birth, 18))
        THROW_EXCEPTION(kInvalidInput, "Subject is under the age of 18");

    // Create a hash of the subject's name and their document ID to use as a subject ID
    const std::string message =
        subject_details.first_name + subject_details.last_name + subject_details.document_id;
    std::vector<uint8_t> message_bytes(message.size(), 0);
    std::copy(message.begin(), message.end(), message_bytes.begin());

    std::array<uint8_t, CORE_SHA_256_LEN> subject_id = Hash::get_SHA_256_digest(message_bytes);

    CBORMap certificate_map;
    certificate_map.insert(onfido_client.server_address(), onfido_client.get_leaf_certificate());
    result.certificate_data = certificate_map.encode_cbor(CORE_MAX_CERTIFICATE_LEN);
    std::vector<uint8_t> certificate_hash = Hash::get_digest(Hash::SHA256, result.certificate_data);

    // Sign the result
    result.binary_proof_data = generate_kyc_proof_data(request.get_proof_id(),
                                                       request.get_server_timestamp(),
                                                       request.get_wallet_public_key(),
                                                       certificate_hash,
                                                       check_result.timestamp,
                                                       subject_id);
    if (request.get_blockchain() == kAlgorand)
        result.signature = ed25519_signing_keys.algorand_sign(result.binary_proof_data,
                                                              request.get_program_hash());
    else
        result.signature = ed25519_signing_keys.sign(result.binary_proof_data);

    result.status = kSuccess;

    return result;
}

CheckResult process_instagram_proof(const InstagramCheckRequestWrapper &request,
                                    const ED25519KeyPair &ed25519_signing_keys)
{
    CheckResult result;
    result.status = kUnknownError;

    request.verify_wallet_signature();

    // The input data is the Instagram authorization code & the proof ID
    const CBORMap decrypted_data(request.get_decrypted_input(), {"ig_auth_code", "proof_id"});

    // The proof ID should match the one passed in the input client info
    const std::string proof_id = decrypted_data.get("proof_id").get_text_string_value();
    if (proof_id != request.get_proof_id())
        THROW_EXCEPTION(kInvalidInput,
                        "proof_id in signed input data doesn't match value passed in client info");

    // Extract the auth code
    const std::string ig_auth_code = decrypted_data.get("ig_auth_code").get_text_string_value();

    // Setup the Instagram client
    const auto api_config = request.get_api_config(0);
    InstagramClient client("instagram.com", api_config, ig_auth_code);

    // Exchange the auth code for an access token & get username
    CBORMap certificate_map;
    client.get_access();
    // Access subdomain uses a different TLS certificate
    certificate_map.insert(client.server_address(), client.get_leaf_certificate());

    // ATTN. get_username & get_account_type use a different server to get_access
    // so need to store the certificate too
    const std::string username = client.get_username();
    const std::string account_type = client.get_account_type();
    certificate_map.insert(client.server_address(), client.get_leaf_certificate());

    result.certificate_data = certificate_map.encode_cbor(CORE_MAX_CERTIFICATE_LEN);

    std::vector<uint8_t> certificate_hash = Hash::get_digest(Hash::SHA256, result.certificate_data);

    // Generate the proof certificate
    result.binary_proof_data = generate_instagram_proof_data(request.get_proof_id(),
                                                             request.get_server_timestamp(),
                                                             request.get_wallet_public_key(),
                                                             certificate_hash,
                                                             username,
                                                             account_type);

    // Sign the certificate data
    if (request.get_blockchain() == kAlgorand)
        result.signature = ed25519_signing_keys.algorand_sign(result.binary_proof_data,
                                                              request.get_program_hash());
    else
        result.signature = ed25519_signing_keys.sign(result.binary_proof_data);

    result.status = kSuccess;

    DEBUG_LOG("Instagram check result");
    DEBUG_HEX_LOG(
        "binary_proof_data", result.binary_proof_data.data(), result.binary_proof_data.size());
    DEBUG_HEX_LOG("signature", result.signature.data(), result.signature.size());

    return result;
}

} // namespace enclave
} // namespace silentdata
