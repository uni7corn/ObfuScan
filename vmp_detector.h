#pragma once

#include "disasm_arm64.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct ExecutableRegionView {
    const uint8_t* data = nullptr;
    size_t size = 0;
    uint64_t virtual_address = 0;
    std::string name;
};

struct AddressRange {
    uint64_t begin = 0;
    uint64_t end = 0;
};

struct VmpAnalysisContext {
    size_t import_count = 0;
    bool has_init_array = false;
    bool has_large_entropy_blob = false;
    bool code_obscured_by_packing = false;
    bool known_runtime = false;
    // A recognized non-VM framework (logging, image, UI, React Native, etc.)
    // is a competing explanation only when structural evidence is sparse.
    // It must not veto a dense, independently closed dispatcher.
    bool known_non_vm_framework = false;
    // Independent runtime evidence classes (basename, identity strings,
    // imported APIs).  Two or more are required for a global interpreter
    // alternative; one class is only a weak hint.
    uint8_t runtime_evidence_classes = 0;
    std::string known_runtime_name;
    bool vmp_metadata_marker = false;
    bool custom_linker_marker = false;
    bool custom_linker_likely = false;
    // A separate high-entropy/arithmetic control-flow-obfuscation profile can
    // explain an isolated dispatcher-like site without claiming a VM.
    bool control_flow_obfuscation_likely = false;
    std::vector<AddressRange> excluded_thunk_ranges;
};

struct VmpCandidateEvidence {
    uint64_t address = 0;
    std::string region;
    std::string kind;
    std::string strength;
    std::string vip_reg;
    std::string opcode_reg;
    std::string target_reg;
    std::vector<std::string> traits;
};

struct VmpMetrics {
    uint64_t executable_bytes = 0;
    uint64_t scanned_bytes = 0;
    uint64_t decoded_candidate_bytes = 0;
    uint64_t instruction_slots = 0;
    size_t raw_indirect_transfers = 0;
    size_t excluded_thunk_sites = 0;
    size_t unique_candidates = 0;
    size_t strong_candidates = 0;
    size_t medium_candidates = 0;
    size_t direct_dispatch_candidates = 0;
    size_t call_dispatch_candidates = 0;
    size_t conditional_dispatch_candidates = 0;
    size_t table_linked_candidates = 0;
    size_t vip_advanced_candidates = 0;
    size_t trampoline_candidates = 0;
    size_t dominant_vip_sites = 0;
    size_t max_cluster_sites = 0;
};

struct VmpDeepResult {
    bool analyzed = false;
    bool observable = false;
    bool possible = false;
    bool scan_truncated = false;
    double score = 0.0;
    double structure_score = 0.0;
    double protection_intent_score = 0.0;
    double alternative_penalty = 0.0;
    double coverage = 0.0;
    std::string outcome = "NOT_ANALYZED";
    std::string confidence = "UNKNOWN";
    std::string profile = "NONE";
    std::string alternative_explanation;
    std::string limitation;
    std::vector<std::string> signals;
    std::vector<VmpCandidateEvidence> candidates;
    VmpMetrics metrics;
};

// Scans every supplied executable region. The fast pass covers all bytes and
// Capstone detail is enabled only around control-flow candidates.
VmpDeepResult analyze_vmp_regions(const std::vector<ExecutableRegionView>& regions,
                                  const VmpAnalysisContext& context);

// Public instruction-stream entrypoint used by tests and embedding callers.
// Each indirect branch address is evaluated once, so overlapping windows cannot
// inflate the score.
VmpDeepResult analyze_vmp_instruction_stream(const std::vector<DisasmInsn>& instructions,
                                             const VmpAnalysisContext& context,
                                             const std::string& region_name = "instruction-stream");
