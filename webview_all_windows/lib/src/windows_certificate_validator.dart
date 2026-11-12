import 'package:flutter/services.dart';

/// Result of [WindowsCertificateValidator.validate].
class WindowsCertificateValidation {
  const WindowsCertificateValidation({required this.trusted, this.reason = ''});

  final bool trusted;

  /// Short diagnostic when [trusted] is false.
  final String reason;
}

/// Validates a TLS server certificate chain with the Windows CryptoAPI against
/// caller-provided roots only (the OS root store is not consulted).
///
/// The SSL server policy for the host is applied (name match, key usage,
/// validity, basic constraints). Revocation is not checked.
abstract final class WindowsCertificateValidator {
  static const MethodChannel _channel = MethodChannel(
    'com.abandoft.webview_all_windows/browser',
  );

  /// Fails closed: any error yields `trusted == false`.
  static Future<WindowsCertificateValidation> validate({
    required String host,
    required String certificatePem,
    required List<String> rootsPem,
    List<String> intermediatesPem = const <String>[],
  }) async {
    try {
      final result = await _channel
          .invokeMapMethod<String, Object?>('validateCertificateChain', {
            'host': host,
            'certificatePem': certificatePem,
            'intermediatesPem': intermediatesPem,
            'rootsPem': rootsPem,
          });
      return WindowsCertificateValidation(
        trusted: result?['trusted'] == true,
        reason: (result?['reason'] as String?) ?? 'no result',
      );
    } on PlatformException catch (error) {
      return WindowsCertificateValidation(
        trusted: false,
        reason: error.message ?? error.code,
      );
    } on MissingPluginException {
      return const WindowsCertificateValidation(
        trusted: false,
        reason: 'native validator unavailable',
      );
    }
  }
}
