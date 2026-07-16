#include "apk_scan_limits.h"

#include <limits>

namespace obfuscan {

ZipPayloadDecision evaluate_zip_payload(const ZipPayloadMetadata& metadata,
                                        const ZipPayloadPolicy& policy) {
    if (metadata.uncompressed_bytes == 0) {
        return ZipPayloadDecision::kEmpty;
    }
    if (metadata.encrypted) {
        return ZipPayloadDecision::kEncrypted;
    }
    if (!metadata.supported) {
        return ZipPayloadDecision::kUnsupported;
    }
    if (metadata.uncompressed_bytes > policy.max_uncompressed_bytes) {
        return ZipPayloadDecision::kTooLarge;
    }

    if (metadata.uncompressed_bytes >= policy.compression_ratio_floor_bytes) {
        if (metadata.compressed_bytes == 0) {
            return ZipPayloadDecision::kExtremeCompressionRatio;
        }

        // Division avoids overflow from compressed_bytes * max_compression_ratio.
        const uint64_t quotient = metadata.uncompressed_bytes / metadata.compressed_bytes;
        const uint64_t remainder = metadata.uncompressed_bytes % metadata.compressed_bytes;
        if (quotient > policy.max_compression_ratio ||
            (quotient == policy.max_compression_ratio && remainder != 0)) {
            return ZipPayloadDecision::kExtremeCompressionRatio;
        }
    }

    return ZipPayloadDecision::kAllow;
}

bool fits_cumulative_budget(uint64_t already_accepted,
                            uint64_t candidate_bytes,
                            uint64_t maximum_bytes) {
    return already_accepted <= maximum_bytes &&
           candidate_bytes <= maximum_bytes - already_accepted;
}

uint64_t saturating_add_u64(uint64_t lhs, uint64_t rhs) {
    const uint64_t maximum = std::numeric_limits<uint64_t>::max();
    return rhs > maximum - lhs ? maximum : lhs + rhs;
}

std::string_view zip_payload_decision_code(ZipPayloadDecision decision) {
    switch (decision) {
        case ZipPayloadDecision::kAllow: return "ALLOW";
        case ZipPayloadDecision::kEmpty: return "EMPTY_ENTRY";
        case ZipPayloadDecision::kEncrypted: return "ENCRYPTED_ENTRY";
        case ZipPayloadDecision::kUnsupported: return "UNSUPPORTED_COMPRESSION";
        case ZipPayloadDecision::kTooLarge: return "ENTRY_TOO_LARGE";
        case ZipPayloadDecision::kExtremeCompressionRatio: return "COMPRESSION_RATIO_LIMIT";
    }
    return "UNKNOWN_POLICY_DECISION";
}

}  // namespace obfuscan
