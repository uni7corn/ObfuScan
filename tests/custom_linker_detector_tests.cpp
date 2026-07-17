#include "custom_linker_detector.h"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

using obfuscan::custom_linker::Confidence;
using obfuscan::custom_linker::Context;
using obfuscan::custom_linker::Outcome;
using obfuscan::custom_linker::Result;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << '\n';
        std::exit(1);
    }
}

std::vector<std::uint8_t> image(
        std::initializer_list<const char*> strings) {
    std::vector<std::uint8_t> bytes;
    for (const char* value : strings) {
        const std::string text(value);
        bytes.insert(bytes.end(), text.begin(), text.end());
        bytes.push_back(0);
    }
    return bytes;
}

std::vector<std::uint8_t> full_loader_image(bool protected_identity = false) {
    auto bytes = image({
        "PT_LOAD", "PT_DYNAMIC", "Elf64_Ehdr",
        "DT_RELA", "DT_JMPREL",
        "DT_NEEDED", "DT_SYMTAB", "DT_STRTAB",
        "call_constructors", "find_library", "link_image", "soinfo",
        "u4proc.linker", "linkerversion: 1.0"
    });
    if (protected_identity) {
        const auto protection = image({
            "libshieldlinker.so", "decrypted payload"
        });
        bytes.insert(bytes.end(), protection.begin(), protection.end());
    }
    return bytes;
}

std::vector<std::string> full_loader_imports() {
    return {
        "mmap", "mprotect", "munmap",
        "open", "pread64", "fstat", "close",
        "dlopen", "dlsym"
    };
}

bool has_code(const Result& result, const std::string& code) {
    return std::find(result.evidence_codes.begin(), result.evidence_codes.end(),
                     code) != result.evidence_codes.end();
}

void test_lld_and_classlinker_are_noise() {
    const auto result = obfuscan::custom_linker::analyze(
        image({"Linker: LLD 14.0.7", "ClassLinker::MakeInitializedClasses"}),
        {"mmap", "mprotect", "munmap", "open", "read", "close",
         "dlopen", "dlsym"});

    expect(result.outcome == Outcome::NONE,
           "LLD/ClassLinker plus common APIs must not imply a custom loader");
    expect(result.counts.generic_linker_noise_hits >= 2,
           "ignored generic linker evidence should remain observable");
    expect(result.counts.explicit_protection_identity_hits == 0,
           "generic linker text must not become a protection identity");
    expect(!result.loader_gate_passed && !result.protection_gate_passed,
           "API capability must not bypass semantic loader gates");
    expect(has_code(result, "GENERIC_LINKER_NOISE_IGNORED"),
           "the reason for ignoring the linker text should be machine-visible");
}

void test_pine_is_hook_alternative() {
    Context context;
    context.basename = "libpine.so";
    context.known_hook_framework = true;
    const auto result = obfuscan::custom_linker::analyze(
        image({
            "top/canyie/pine/Pine", "PineNativeInlineHookFuncNoBackup",
            "ArtMethod", "pine_direct_jump_trampoline", "ClassLinker",
            "Linker: LLD 14.0.7"
        }),
        {"mmap", "mprotect", "munmap", "lseek", "close"}, context);

    expect(result.outcome == Outcome::ELF_INSPECTION_OR_HOOK,
           "Pine must be explained as a Hook framework");
    expect(result.confidence == Confidence::HIGH,
           "Pine identity plus Hook primitives should be high-confidence");
    expect(result.hook_alternative,
           "the Hook alternative must be retained structurally");
    expect(!result.loader_gate_passed && !result.protection_gate_passed,
           "Pine mapping APIs must not satisfy a custom-loader gate");
    expect(result.counts.explicit_protection_identity_hits == 0,
           "ClassLinker/LLD must not be counted as protection identity");
}

void test_pine_basename_match_is_exact() {
    Context context;
    context.basename = "libpineapple.so";
    const auto result = obfuscan::custom_linker::analyze(
        image({"ordinary utility library"}), {}, context);

    expect(result.outcome == Outcome::NONE,
           "a library whose name merely contains pine must not become a Hook framework");
    expect(!result.hook_alternative,
           "Pine basename matching must be exact");
}

void test_weak_hook_names_need_corroboration() {
    Context basename_context;
    basename_context.basename = "libwhaleaudio.so";
    const auto basename_result = obfuscan::custom_linker::analyze(
        image({"ordinary audio utility"}), {}, basename_context);
    expect(basename_result.outcome == Outcome::NONE &&
               !basename_result.hook_alternative,
           "a Hook-family substring inside an unrelated basename must be ignored");

    const auto single_string = obfuscan::custom_linker::analyze(
        image({"WhaleHook compatibility string"}), {});
    expect(single_string.outcome == Outcome::NONE &&
               !single_string.hook_alternative,
           "one Hook name without a primitive or exact identity must not classify");
}

void test_generic_dlopen_library_is_not_loader() {
    const auto result = obfuscan::custom_linker::analyze(
        image({"plugin manager", "load extension"}),
        {"dlopen", "dlsym", "mmap", "mprotect", "munmap",
         "open", "read", "close"});

    expect(result.outcome == Outcome::NONE,
           "a generic plugin/dlopen library is not a custom loader");
    expect(result.counts.dynamic_link_import_hits == 2,
           "dynamic-link capability should still be counted");
    expect(result.counts.independent_loader_axes < 4,
           "API-only evidence must not manufacture four semantic axes");
    expect(has_code(result, "API_CAPABILITY_NOT_DECISIVE"),
           "API-only rejection should be explicit");
}

void test_elf_inspector_is_not_loader() {
    const auto result = obfuscan::custom_linker::analyze(
        image({
            "PT_LOAD", "PT_DYNAMIC", "DT_RELA",
            "DT_NEEDED", "DT_SYMTAB", "symbolizer backtrace"
        }),
        {"dl_iterate_phdr", "dladdr", "dlsym"});

    expect(result.outcome == Outcome::ELF_INSPECTION_OR_HOOK,
           "an ELF symbolizer should remain an inspection profile");
    expect(result.counts.independent_loader_axes == 3,
           "the fixture should expose parser, relocation and symbol axes only");
    expect(!result.loader_gate_passed,
           "inspection without mapping/execution must not be a loader");
}

void test_source_axis_requires_open_and_read() {
    const auto semantic_image = image({
        "PT_LOAD", "PT_DYNAMIC", "DT_RELA", "DT_NEEDED", "DT_SYMTAB"
    });
    const std::vector<std::string> mapping = {
        "mmap", "mprotect", "munmap"
    };

    auto read_only_imports = mapping;
    read_only_imports.insert(read_only_imports.end(),
                             {"read", "lseek", "close"});
    const auto read_only = obfuscan::custom_linker::analyze(
        semantic_image, read_only_imports);
    expect(!read_only.loader_gate_passed,
           "read/lseek/close without an opener must not form a source axis");
    expect(!has_code(read_only, "FILE_BACKED_SOURCE_CAPABILITY"),
           "the incomplete read side must not be reported as source acquisition");

    auto open_only_imports = mapping;
    open_only_imports.insert(open_only_imports.end(), {"openat", "close"});
    const auto open_only = obfuscan::custom_linker::analyze(
        semantic_image, open_only_imports);
    expect(!open_only.loader_gate_passed,
           "open/close without a reader must not form a source axis");
    expect(!has_code(open_only, "FILE_BACKED_SOURCE_CAPABILITY"),
           "the incomplete open side must not be reported as source acquisition");

    auto complete_imports = mapping;
    complete_imports.insert(complete_imports.end(), {"fopen", "fread", "close"});
    const auto complete = obfuscan::custom_linker::analyze(
        semantic_image, complete_imports);
    expect(complete.outcome == Outcome::CUSTOM_LOADER_COMPONENT,
           "fopen plus fread should complete the source-acquisition axis");
    expect(has_code(complete, "FILE_BACKED_SOURCE_CAPABILITY"),
           "a complete opener/reader pair should remain visible");
}

void test_mapping_axis_requires_mprotect() {
    const auto semantic_image = image({
        "PT_LOAD", "PT_DYNAMIC", "DT_RELA", "DT_NEEDED", "DT_SYMTAB"
    });
    const auto read_only_mapping = obfuscan::custom_linker::analyze(
        semantic_image, {"mmap", "munmap", "open", "read", "close"});
    expect(!read_only_mapping.loader_gate_passed,
           "mmap plus munmap is read-only inspection, not executable loading");
    expect(!has_code(read_only_mapping, "MEMORY_MAPPING_CAPABILITY"),
           "munmap must not complete the mapping/execution axis");

    const auto permission_transition = obfuscan::custom_linker::analyze(
        semantic_image,
        {"mmap", "mprotect", "munmap", "open", "read", "close"});
    expect(permission_transition.outcome == Outcome::CUSTOM_LOADER_COMPONENT,
           "mmap plus mprotect may complete an otherwise closed loader chain");
}

void test_full_loader_component() {
    const auto result = obfuscan::custom_linker::analyze(
        full_loader_image(), full_loader_imports());

    expect(result.outcome == Outcome::CUSTOM_LOADER_COMPONENT,
           "a closed manual-loader implementation should be recognized");
    expect(result.loader_gate_passed && result.loader_component(),
           "the semantic loader gate must pass");
    expect(!result.protection_gate_passed && !result.likely_protection(),
           "loader functionality alone must not be called protection");
    expect(result.counts.independent_loader_axes >= 5,
           "the full loader must span at least five independent axes");
    expect(result.loader_score >= 0.80,
           "the complete loader should retain a strong loader score");
}

void test_hook_evidence_does_not_hide_a_full_loader_component() {
    auto bytes = full_loader_image();
    const auto hook = image({"WhaleHook", "inline hook trampoline"});
    bytes.insert(bytes.end(), hook.begin(), hook.end());
    const auto result = obfuscan::custom_linker::analyze(
        bytes, full_loader_imports());

    expect(result.hook_alternative,
           "the competing Hook explanation should remain observable");
    expect(result.outcome == Outcome::CUSTOM_LOADER_COMPONENT,
           "corroborated Hook evidence must not hide a closed loader implementation");
}

void test_protected_loader_requires_independent_protection() {
    Context context;
    context.high_entropy_payload = true;
    const auto result = obfuscan::custom_linker::analyze(
        full_loader_image(true), full_loader_imports(), context);

    expect(result.outcome == Outcome::LIKELY_CUSTOM_LINKER_PROTECTION,
           "a complete loader plus explicit protection must classify high");
    expect(result.loader_gate_passed && result.protection_gate_passed,
           "both independent gates must pass");
    expect(result.counts.explicit_protection_identity_hits >= 1,
           "the protection identity must be counted separately");
    expect(result.counts.protection_axes >= 2,
           "identity and payload should remain independent protection axes");
    expect(result.protection_score >= 0.80,
           "independent protection evidence should produce a strong score");
}

void test_relocation_aliases_and_payload_semantics() {
    Context context;
    context.high_entropy_payload = true;
    const auto result = obfuscan::custom_linker::analyze(
        image({
            "PT_LOAD", "PT_DYNAMIC", "Elf64_Ehdr",
            "reloc_library", "reloc_relative",
            "DT_NEEDED", "DT_SYMTAB", "DT_STRTAB",
            "call_constructors", "load_library_wrap", "link_image",
            "libshieldlinker.so", "payload PT_LOAD", "payload decrypt"
        }),
        full_loader_imports(), context);

    expect(result.counts.relocation_hits >= 2,
           "reloc_library/reloc_relative must feed the relocation axis");
    expect(result.counts.explicit_payload_identity_hits >= 2,
           "payload mapping/decrypt semantics must be counted explicitly");
    expect(result.outcome == Outcome::LIKELY_CUSTOM_LINKER_PROTECTION,
           "liboutput64-like loader and payload semantics should classify high");
}

void test_entropy_and_zip_are_context_only() {
    Context context;
    context.high_entropy_payload = true;
    context.packed_container = true;
    const auto result = obfuscan::custom_linker::analyze(
        full_loader_image(), full_loader_imports(), context);

    expect(result.outcome == Outcome::CUSTOM_LOADER_COMPONENT,
           "entropy/ZIP context without payload semantics is not protection");
    expect(result.counts.explicit_payload_identity_hits == 0,
           "context must not manufacture a payload identity hit");
    expect(result.counts.protection_axes == 0 &&
               !result.protection_gate_passed,
           "context-only packing evidence must remain outside the protection gate");
    expect(has_code(result, "PAYLOAD_CONTEXT_ONLY"),
           "the supporting-only payload context should remain explainable");
}

void test_protection_marker_and_apis_are_still_insufficient() {
    const auto result = obfuscan::custom_linker::analyze(
        image({"libshieldlinker.so", "Linker: LLD 18.0.0"}),
        {"mmap", "mprotect", "munmap", "dlopen", "dlsym"});

    expect(result.outcome == Outcome::NONE,
           "a protection name plus common APIs cannot replace loader semantics");
    expect(result.protection_score > 0.0 && !result.protection_gate_passed,
           "protection evidence may score but must remain gated");
}

void test_hook_and_protection_can_coexist_only_with_full_chain() {
    auto bytes = full_loader_image(true);
    const auto pine = image({
        "top/canyie/pine/Pine", "PineNativeInlineHook", "ArtMethod",
        "pine_bridge_jump_trampoline"
    });
    bytes.insert(bytes.end(), pine.begin(), pine.end());

    Context context;
    context.basename = "libpine_protected.so";
    context.known_hook_framework = true;
    context.high_entropy_payload = true;
    const auto result = obfuscan::custom_linker::analyze(
        bytes, full_loader_imports(), context);

    expect(result.hook_alternative,
           "coexistence must not erase the Hook explanation");
    expect(result.outcome == Outcome::LIKELY_CUSTOM_LINKER_PROTECTION,
           "a complete independent protection chain may coexist with Hooking");
    expect(result.counts.independent_loader_axes >= 5,
           "Hook override requires the stricter multi-axis loader chain");
}

void test_incomplete_hook_cannot_be_promoted_by_payload() {
    Context context;
    context.basename = "libpine.so";
    context.known_hook_framework = true;
    context.high_entropy_payload = true;
    const auto result = obfuscan::custom_linker::analyze(
        image({"top/canyie/pine/Pine", "trampoline", "libshieldlinker.so"}),
        {"mmap", "mprotect", "munmap", "dlopen", "dlsym"}, context);

    expect(result.outcome == Outcome::ELF_INSPECTION_OR_HOOK,
           "payload/identity cannot promote an incomplete Hook loader chain");
    expect(!result.protection_gate_passed,
           "the stricter Hook coexistence gate must reject incomplete semantics");
}

void test_sectionless_is_neutral() {
    Context ordinary_context;
    ordinary_context.sectionless = true;
    const auto ordinary = obfuscan::custom_linker::analyze(
        image({"Linker: LLD 18.0.0"}), {"dlopen", "dlsym"},
        ordinary_context);
    expect(ordinary.outcome == Outcome::NONE,
           "sectionless alone must not imply packing or a custom loader");
    expect(has_code(ordinary, "SECTIONLESS_ELF_NEUTRAL"),
           "sectionless status should remain visible as neutral context");

    Context loader_context;
    loader_context.sectionless = true;
    const auto loader = obfuscan::custom_linker::analyze(
        full_loader_image(), full_loader_imports(), loader_context);
    expect(loader.outcome == Outcome::CUSTOM_LOADER_COMPONENT,
           "sectionless ELF must still classify from observable loader semantics");
}

void test_obscured_packed_payload_is_inconclusive() {
    Context context;
    context.sectionless = true;
    context.code_obscured_by_packing = true;
    context.packed_container = true;
    const auto result = obfuscan::custom_linker::analyze(
        image({"Linker: LLD"}), {}, context);

    expect(result.outcome == Outcome::INCONCLUSIVE_PACKED,
           "hidden loader code must be inconclusive rather than a positive");
    expect(result.confidence == Confidence::UNKNOWN,
           "unobservable packed code must not claim confidence");
    expect(!result.loader_gate_passed && !result.protection_gate_passed,
           "a packed payload alone cannot pass either semantic gate");
}

}  // namespace

int main() {
    test_lld_and_classlinker_are_noise();
    test_pine_is_hook_alternative();
    test_pine_basename_match_is_exact();
    test_weak_hook_names_need_corroboration();
    test_generic_dlopen_library_is_not_loader();
    test_elf_inspector_is_not_loader();
    test_source_axis_requires_open_and_read();
    test_mapping_axis_requires_mprotect();
    test_full_loader_component();
    test_hook_evidence_does_not_hide_a_full_loader_component();
    test_protected_loader_requires_independent_protection();
    test_relocation_aliases_and_payload_semantics();
    test_entropy_and_zip_are_context_only();
    test_protection_marker_and_apis_are_still_insufficient();
    test_hook_and_protection_can_coexist_only_with_full_chain();
    test_incomplete_hook_cannot_be_promoted_by_payload();
    test_sectionless_is_neutral();
    test_obscured_packed_payload_is_inconclusive();
    std::cout << "[PASS] custom_linker_detector_tests\n";
    return 0;
}
