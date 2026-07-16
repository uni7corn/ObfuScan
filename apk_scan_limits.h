#pragma once

#include <cstdint>
#include <string_view>

namespace obfuscan {

struct ApkScanLimits {
    static constexpr uint64_t kMaxApkBytes = 1024ULL * 1024ULL * 1024ULL;
    static constexpr uint64_t kMaxZipMetadataBytes = 64ULL * 1024ULL * 1024ULL;
    static constexpr uint64_t kMaxZipEntries = 20000;
    static constexpr uint64_t kMaxCandidateSoEntries = 256;
    static constexpr uint64_t kMaxSingleSoBytes = 128ULL * 1024ULL * 1024ULL;
    static constexpr uint64_t kMaxTotalRelevantSoBytes = 512ULL * 1024ULL * 1024ULL;
    static constexpr uint64_t kMaxCompressionRatio = 200;
    static constexpr uint64_t kCompressionRatioFloorBytes = 1024ULL * 1024ULL;

    static constexpr uint64_t kMaxInnerZipMetadataBytes = 16ULL * 1024ULL * 1024ULL;
    static constexpr uint64_t kMaxInnerZipEntries = 1024;
    static constexpr uint64_t kMaxSingleInnerEntryBytes = 128ULL * 1024ULL * 1024ULL;
    static constexpr uint64_t kMaxTotalInnerEntryBytes = 256ULL * 1024ULL * 1024ULL;

    static constexpr uint64_t kMaxRecordedDiagnostics = 64;
};

struct ZipPayloadPolicy {
    uint64_t max_uncompressed_bytes = 0;
    uint64_t max_compression_ratio = 0;
    uint64_t compression_ratio_floor_bytes = 0;
};

enum class ZipPayloadDecision {
    kAllow,
    kEmpty,
    kEncrypted,
    kUnsupported,
    kTooLarge,
    kExtremeCompressionRatio,
};

struct ZipPayloadMetadata {
    uint64_t compressed_bytes = 0;
    uint64_t uncompressed_bytes = 0;
    bool encrypted = false;
    bool supported = true;
};

ZipPayloadDecision evaluate_zip_payload(const ZipPayloadMetadata& metadata,
                                        const ZipPayloadPolicy& policy);

bool fits_cumulative_budget(uint64_t already_accepted,
                            uint64_t candidate_bytes,
                            uint64_t maximum_bytes);

uint64_t saturating_add_u64(uint64_t lhs, uint64_t rhs);

std::string_view zip_payload_decision_code(ZipPayloadDecision decision);

}  // namespace obfuscan
