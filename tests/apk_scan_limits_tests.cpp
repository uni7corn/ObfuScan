#include "apk_scan_limits.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }
}

obfuscan::ZipPayloadPolicy outer_policy() {
    return {
        obfuscan::ApkScanLimits::kMaxSingleSoBytes,
        obfuscan::ApkScanLimits::kMaxCompressionRatio,
        obfuscan::ApkScanLimits::kCompressionRatioFloorBytes,
    };
}

}  // namespace

int main() {
    using obfuscan::ApkScanLimits;
    using obfuscan::ZipPayloadDecision;
    using obfuscan::ZipPayloadMetadata;

    const auto policy = outer_policy();

    // A verified large-corpus sample contains an SO of about 31 MiB. Keep a
    // realistic 32 MiB entry comfortably inside every public-deployment limit.
    expect(obfuscan::evaluate_zip_payload(
               {24ULL * 1024 * 1024, 32ULL * 1024 * 1024, false, true}, policy) ==
               ZipPayloadDecision::kAllow,
           "realistic 32 MiB SO must remain accepted");

    expect(obfuscan::evaluate_zip_payload(
               {1, 0, false, true}, policy) == ZipPayloadDecision::kEmpty,
           "empty SO must be rejected before extraction");
    expect(obfuscan::evaluate_zip_payload(
               {1024, 4096, true, false}, policy) == ZipPayloadDecision::kEncrypted,
           "encryption must take precedence over generic unsupported status");
    expect(obfuscan::evaluate_zip_payload(
               {1024, 4096, false, false}, policy) == ZipPayloadDecision::kUnsupported,
           "unsupported compression must be rejected");
    expect(obfuscan::evaluate_zip_payload(
               {64ULL * 1024 * 1024, ApkScanLimits::kMaxSingleSoBytes + 1, false, true},
               policy) == ZipPayloadDecision::kTooLarge,
           "single-SO limit must be strict");

    expect(obfuscan::evaluate_zip_payload(
               {1024, 2ULL * 1024 * 1024, false, true}, policy) ==
               ZipPayloadDecision::kExtremeCompressionRatio,
           "large compression bomb must be rejected");
    expect(obfuscan::evaluate_zip_payload(
               {4096, ApkScanLimits::kCompressionRatioFloorBytes - 1, false, true}, policy) ==
               ZipPayloadDecision::kAllow,
           "small entries below the ratio floor must not be false positives");

    const uint64_t ratio_denominator = 512ULL * 1024;
    const uint64_t exactly_200_to_1 = ratio_denominator * 200;
    expect(obfuscan::evaluate_zip_payload(
               {ratio_denominator, exactly_200_to_1, false, true}, policy) ==
               ZipPayloadDecision::kAllow,
           "exactly 200:1 must be accepted");
    expect(obfuscan::evaluate_zip_payload(
               {ratio_denominator, exactly_200_to_1 + 1, false, true}, policy) ==
               ZipPayloadDecision::kExtremeCompressionRatio,
           "more than 200:1 must be rejected without multiplication overflow");

    expect(obfuscan::fits_cumulative_budget(
               480ULL * 1024 * 1024, 32ULL * 1024 * 1024,
               ApkScanLimits::kMaxTotalRelevantSoBytes),
           "realistic cumulative boundary must be accepted");
    expect(!obfuscan::fits_cumulative_budget(
               480ULL * 1024 * 1024, 32ULL * 1024 * 1024 + 1,
               ApkScanLimits::kMaxTotalRelevantSoBytes),
           "cumulative boundary must be strict");

    expect(obfuscan::saturating_add_u64(UINT64_MAX - 3, 9) == UINT64_MAX,
           "declared-size telemetry must saturate instead of wrapping");

    std::cout << "apk_scan_limits_tests: OK\n";
    return 0;
}
