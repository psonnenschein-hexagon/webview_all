#ifndef WEBVIEW_ALL_WINDOWS_UTIL_CERTIFICATE_VALIDATOR_H_
#define WEBVIEW_ALL_WINDOWS_UTIL_CERTIFICATE_VALIDATOR_H_

#include <string>
#include <vector>

namespace webview_all_windows {

struct CertificateValidationResult {
  bool trusted = false;
  // Empty when trusted; otherwise a short diagnostic (never sensitive).
  std::string reason;
};

// Validates a server certificate chain with the Windows CryptoAPI, trusting
// ONLY the given roots (the OS root store is not consulted) and applying the
// SSL server policy for `host` (name match, EKU, validity, basic constraints).
// Revocation is not checked. Fails closed on every error.
//
// All certificates are PEM; `roots_pem` entries may contain several
// concatenated certificates.
CertificateValidationResult ValidateServerCertificate(
    const std::string &leaf_pem,
    const std::vector<std::string> &intermediates_pem,
    const std::vector<std::string> &roots_pem, const std::string &host);

} // namespace webview_all_windows

#endif
