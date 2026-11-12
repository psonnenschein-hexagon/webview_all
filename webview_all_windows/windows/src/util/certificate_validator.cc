#include "util/certificate_validator.h"

#include <windows.h>
#include <wincrypt.h>

#include <memory>

#include "util/string_converter.h"

#pragma comment(lib, "crypt32.lib")

namespace webview_all_windows {
namespace {

struct CertContextDeleter {
  void operator()(const CERT_CONTEXT *c) const { CertFreeCertificateContext(c); }
};
struct StoreDeleter {
  void operator()(HCERTSTORE s) const { CertCloseStore(s, 0); }
};
struct EngineDeleter {
  void operator()(HCERTCHAINENGINE e) const {
    CertFreeCertificateChainEngine(e);
  }
};
struct ChainDeleter {
  void operator()(const CERT_CHAIN_CONTEXT *c) const {
    CertFreeCertificateChain(c);
  }
};

using CertPtr = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;
using StorePtr = std::unique_ptr<void, StoreDeleter>;
using EnginePtr = std::unique_ptr<void, EngineDeleter>;
using ChainPtr = std::unique_ptr<const CERT_CHAIN_CONTEXT, ChainDeleter>;

constexpr char kEnd[] = "-----END CERTIFICATE-----";

// Splits concatenated PEM text into DER blobs. Returns false on malformed input.
bool PemToDerList(const std::string &pem,
                  std::vector<std::vector<BYTE>> *out) {
  size_t pos = 0;
  bool any = false;
  while (true) {
    const size_t end = pem.find(kEnd, pos);
    if (end == std::string::npos) break;
    const size_t stop = end + sizeof(kEnd) - 1;
    const std::string block = pem.substr(pos, stop - pos);
    pos = stop;
    DWORD size = 0;
    if (!CryptStringToBinaryA(block.c_str(), static_cast<DWORD>(block.size()),
                              CRYPT_STRING_BASE64HEADER, nullptr, &size,
                              nullptr, nullptr) ||
        size == 0) {
      return false;
    }
    std::vector<BYTE> der(size);
    if (!CryptStringToBinaryA(block.c_str(), static_cast<DWORD>(block.size()),
                              CRYPT_STRING_BASE64HEADER, der.data(), &size,
                              nullptr, nullptr)) {
      return false;
    }
    der.resize(size);
    out->push_back(std::move(der));
    any = true;
  }
  return any;
}

bool AddAll(HCERTSTORE store, const std::vector<std::string> &pems,
            CertPtr *first) {
  for (const auto &pem : pems) {
    std::vector<std::vector<BYTE>> ders;
    if (!PemToDerList(pem, &ders)) return false;
    for (const auto &der : ders) {
      const CERT_CONTEXT *added = nullptr;
      if (!CertAddEncodedCertificateToStore(
              store, X509_ASN_ENCODING, der.data(),
              static_cast<DWORD>(der.size()), CERT_STORE_ADD_USE_EXISTING,
              &added)) {
        return false;
      }
      if (first && !*first) {
        first->reset(added);
      } else {
        CertFreeCertificateContext(added);
      }
    }
  }
  return true;
}

CertificateValidationResult Fail(const std::string &reason) {
  return {false, reason};
}

} // namespace

CertificateValidationResult ValidateServerCertificate(
    const std::string &leaf_pem,
    const std::vector<std::string> &intermediates_pem,
    const std::vector<std::string> &roots_pem, const std::string &host) {
  if (leaf_pem.empty() || roots_pem.empty() || host.empty()) {
    return Fail("missing input");
  }

  StorePtr roots(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr));
  StorePtr extra(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr));
  if (!roots || !extra) return Fail("store creation failed");

  CertPtr root_first;
  if (!AddAll(roots.get(), roots_pem, &root_first) || !root_first) {
    return Fail("invalid root certificate");
  }
  CertPtr leaf;
  if (!AddAll(extra.get(), {leaf_pem}, &leaf) || !leaf) {
    return Fail("invalid server certificate");
  }
  if (!AddAll(extra.get(), intermediates_pem, nullptr)) {
    return Fail("invalid intermediate certificate");
  }

  CERT_CHAIN_ENGINE_CONFIG engine_config = {};
  engine_config.cbSize = sizeof(engine_config);
  engine_config.hExclusiveRoot = roots.get();
  HCERTCHAINENGINE raw_engine = nullptr;
  if (!CertCreateCertificateChainEngine(&engine_config, &raw_engine)) {
    return Fail("chain engine creation failed");
  }
  EnginePtr engine(raw_engine);

  CERT_ENHKEY_USAGE usage = {};
  CERT_CHAIN_PARA chain_para = {};
  chain_para.cbSize = sizeof(chain_para);
  chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
  chain_para.RequestedUsage.Usage = usage;

  const CERT_CHAIN_CONTEXT *raw_chain = nullptr;
  if (!CertGetCertificateChain(engine.get(), leaf.get(), nullptr, extra.get(),
                               &chain_para, 0, nullptr, &raw_chain)) {
    return Fail("chain building failed");
  }
  ChainPtr chain(raw_chain);

  const std::wstring wide_host = util::Utf16FromUtf8(host);
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para = {};
  ssl_para.cbSize = sizeof(ssl_para);
  ssl_para.dwAuthType = AUTHTYPE_SERVER;
  ssl_para.pwszServerName = const_cast<wchar_t *>(wide_host.c_str());

  CERT_CHAIN_POLICY_PARA policy_para = {};
  policy_para.cbSize = sizeof(policy_para);
  policy_para.pvExtraPolicyPara = &ssl_para;

  CERT_CHAIN_POLICY_STATUS status = {};
  status.cbSize = sizeof(status);
  if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.get(),
                                        &policy_para, &status)) {
    return Fail("policy evaluation failed");
  }
  if (status.dwError != 0) {
    return Fail("chain policy error 0x" + std::to_string(status.dwError));
  }
  return {true, ""};
}

} // namespace webview_all_windows
