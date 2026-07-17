#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace obfuscan::custom_linker {

enum class Outcome {
    NONE,
    ELF_INSPECTION_OR_HOOK,
    CUSTOM_LOADER_COMPONENT,
    LIKELY_CUSTOM_LINKER_PROTECTION,
    INCONCLUSIVE_PACKED
};

enum class Confidence {
    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH
};

struct Context {
    std::string basename;
    bool known_hook_framework = false;
    bool known_runtime_framework = false;
    bool sectionless = false;
    bool code_obscured_by_packing = false;
    bool high_entropy_payload = false;
    bool packed_container = false;
    bool loaded_from_assets = false;
    bool protected_client_relationship = false;
};

struct EvidenceCounts {
    std::size_t generic_linker_noise_hits = 0;
    std::size_t hook_identity_hits = 0;
    std::size_t hook_primitive_hits = 0;
    std::size_t explicit_loader_identity_hits = 0;
    std::size_t explicit_protection_identity_hits = 0;
    std::size_t explicit_payload_identity_hits = 0;
    std::size_t elf_layout_hits = 0;
    std::size_t relocation_hits = 0;
    std::size_t dependency_symbol_hits = 0;
    std::size_t constructor_hits = 0;
    std::size_t linker_internal_hits = 0;
    std::size_t mapping_import_hits = 0;
    std::size_t file_source_import_hits = 0;
    std::size_t dynamic_link_import_hits = 0;
    std::size_t independent_loader_axes = 0;
    std::size_t protection_axes = 0;
};

struct Result {
    Outcome outcome = Outcome::NONE;
    Confidence confidence = Confidence::LOW;
    EvidenceCounts counts;
    double loader_score = 0.0;
    double protection_score = 0.0;
    bool hook_alternative = false;
    bool loader_gate_passed = false;
    bool protection_gate_passed = false;
    std::vector<std::string> evidence_codes;

    bool loader_component() const noexcept {
        return outcome == Outcome::CUSTOM_LOADER_COMPONENT ||
               outcome == Outcome::LIKELY_CUSTOM_LINKER_PROTECTION;
    }

    bool likely_protection() const noexcept {
        return outcome == Outcome::LIKELY_CUSTOM_LINKER_PROTECTION;
    }
};

Result analyze(const std::vector<std::uint8_t>& image,
               const std::vector<std::string>& imports,
               const Context& context = {});

const char* outcome_code(Outcome outcome) noexcept;
const char* confidence_code(Confidence confidence) noexcept;

}  // namespace obfuscan::custom_linker
