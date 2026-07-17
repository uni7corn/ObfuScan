#include "custom_linker_detector.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace obfuscan::custom_linker {
namespace {

unsigned char ascii_lower(unsigned char value) {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<unsigned char>(value + ('a' - 'A'));
    }
    return value;
}

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(ascii_lower(c)); });
    return value;
}

bool contains_icase(const std::vector<std::uint8_t>& image,
                    std::string_view needle) {
    if (needle.empty() || needle.size() > image.size()) return false;
    return std::search(image.begin(), image.end(), needle.begin(), needle.end(),
        [](std::uint8_t lhs, char rhs) {
            return ascii_lower(lhs) ==
                   ascii_lower(static_cast<unsigned char>(rhs));
        }) != image.end();
}

std::size_t count_needles(const std::vector<std::uint8_t>& image,
                          std::initializer_list<std::string_view> needles) {
    std::size_t count = 0;
    for (const auto needle : needles) {
        if (contains_icase(image, needle)) ++count;
    }
    return count;
}

std::unordered_set<std::string> normalized_imports(
        const std::vector<std::string>& imports) {
    std::unordered_set<std::string> normalized;
    for (auto symbol : imports) {
        symbol = lower_ascii(std::move(symbol));
        const std::size_t version = symbol.find('@');
        if (version != std::string::npos) symbol.resize(version);
        if (!symbol.empty()) normalized.insert(std::move(symbol));
    }
    return normalized;
}

std::size_t count_imports(
        const std::unordered_set<std::string>& imports,
        std::initializer_list<std::string_view> wanted) {
    std::size_t count = 0;
    for (const auto symbol : wanted) {
        if (imports.count(std::string(symbol)) != 0) ++count;
    }
    return count;
}

bool has_import(const std::unordered_set<std::string>& imports,
                std::initializer_list<std::string_view> wanted) {
    return count_imports(imports, wanted) != 0;
}

bool contains_any(std::string_view value,
                  std::initializer_list<std::string_view> needles) {
    for (const auto needle : needles) {
        if (value.find(needle) != std::string_view::npos) return true;
    }
    return false;
}

double clamp01(double value) {
    return std::max(0.0, std::min(1.0, value));
}

void add_code(Result& result, const char* code, bool present) {
    if (present) result.evidence_codes.emplace_back(code);
}

}  // namespace

const char* outcome_code(Outcome outcome) noexcept {
    switch (outcome) {
        case Outcome::NONE: return "NONE";
        case Outcome::ELF_INSPECTION_OR_HOOK: return "ELF_INSPECTION_OR_HOOK";
        case Outcome::CUSTOM_LOADER_COMPONENT: return "CUSTOM_LOADER_COMPONENT";
        case Outcome::LIKELY_CUSTOM_LINKER_PROTECTION:
            return "LIKELY_CUSTOM_LINKER_PROTECTION";
        case Outcome::INCONCLUSIVE_PACKED: return "INCONCLUSIVE_PACKED";
    }
    return "NONE";
}

const char* confidence_code(Confidence confidence) noexcept {
    switch (confidence) {
        case Confidence::UNKNOWN: return "UNKNOWN";
        case Confidence::LOW: return "LOW";
        case Confidence::MEDIUM: return "MEDIUM";
        case Confidence::HIGH: return "HIGH";
    }
    return "UNKNOWN";
}

Result analyze(const std::vector<std::uint8_t>& image,
               const std::vector<std::string>& imports,
               const Context& context) {
    Result result;
    EvidenceCounts& counts = result.counts;
    const std::string basename = lower_ascii(context.basename);
    const auto imported = normalized_imports(imports);

    // "linker", ClassLinker and compiler banners describe many ordinary
    // runtimes.  They are retained as an explanation only and never feed a
    // loader or protection gate.
    if (contains_icase(image, "linker")) ++counts.generic_linker_noise_hits;
    counts.generic_linker_noise_hits += count_needles(image, {
        "Linker: LLD", "ClassLinker", "/system/bin/linker",
        "/apex/com.android.runtime/bin/linker", "linker64"
    });

    const std::size_t hook_string_hits = count_needles(image, {
        "top/canyie/pine", "top.canyie.pine", "PineNativeInlineHook",
        "pine_direct_jump_trampoline", "libpine.so", "ShadowHook",
        "ByteHook", "DobbyHook", "libdobby", "libxhook", "SandHook",
        "WhaleHook", "frida-gum"
    });
    static const std::unordered_set<std::string> known_hook_basenames = {
        "libpine.so", "libpinehook.so", "libshadowhook.so",
        "libbytehook.so", "libdobby.so", "libxhook.so",
        "libsandhook.so", "libwhale.so", "libfrida-gum.so",
        "libfrida-gadget.so"
    };
    const bool exact_hook_basename =
        known_hook_basenames.count(basename) != 0;
    counts.hook_identity_hits = hook_string_hits +
        static_cast<std::size_t>(exact_hook_basename) +
        static_cast<std::size_t>(context.known_hook_framework);

    counts.hook_primitive_hits = count_needles(image, {
        "ArtMethod", "trampoline", "inline hook", "InlineHook",
        "RegisterNatives", "quick_entrypoint", "interpreter_entrypoint",
        "ScopedMemoryAccessProtection"
    });

    // These identify a loader implementation, not necessarily protection.
    counts.explicit_loader_identity_hits = count_needles(image, {
        "u4proc.linker", "linkerversion:", "/linker/linker.c",
        "/linker/uc_linker", "manual elf loader", "custom elf loader"
    });

    // Only protection-specific identities are positive.  The naked word
    // "linker" is intentionally absent.
    counts.explicit_protection_identity_hits = count_needles(image, {
        "customlinker", "shelllinker", "protectlinker",
        "libshieldlinker.so"
    });
    if (contains_any(basename, {
            "customlinker", "shelllinker", "protectlinker",
            "libshieldlinker"})) {
        ++counts.explicit_protection_identity_hits;
    }

    // Payload is a protection axis only when the image describes an actual
    // decrypt/decompress/protected-payload operation.  Entropy, ZIP wrapping
    // and an assets path are supporting context, never payload identity.
    counts.explicit_payload_identity_hits = count_needles(image, {
        "decrypted payload", "decrypt payload", "payload decrypt",
        "decrypting payload", "encrypted payload", "uncompress payload",
        "payload uncompress", "decompress payload", "payload decompress",
        "protected payload", "payload PT_LOAD"
    });

    counts.elf_layout_hits = count_needles(image, {
        "PT_LOAD", "PT_DYNAMIC", "Elf64_Ehdr", "Elf64_Phdr",
        "Elf32_Ehdr", "Elf32_Phdr", "load_segments", "map_segments",
        "reserve_address_space", "load_library_wrap"
    });
    counts.relocation_hits = count_needles(image, {
        "DT_RELA", "DT_JMPREL", "DT_PLTREL", "R_AARCH64_", "R_ARM_",
        "apply_reloc", "relocate_symbol", "relocate_phdr", "reloc_library",
        "reloc_relative"
    });
    counts.dependency_symbol_hits = count_needles(image, {
        "DT_NEEDED", "DT_SYMTAB", "DT_STRTAB", "DT_GNU_HASH", "DT_HASH",
        "find_library", "lookup_symbol", "resolve_symbol", "link_image"
    });
    counts.constructor_hits = count_needles(image, {
        "DT_INIT_ARRAY", "DT_FINI_ARRAY", "call_constructors",
        "call_destructors", "call_array"
    });
    counts.linker_internal_hits = count_needles(image, {
        "soinfo", "solist", "android_namespace", "__loader_dlopen",
        "call_constructors", "find_library", "link_image"
    });

    counts.mapping_import_hits = count_imports(imported, {
        "mmap", "mmap64", "mprotect", "munmap", "mremap", "memfd_create"
    });
    counts.file_source_import_hits = count_imports(imported, {
        "open", "open64", "openat", "fopen", "fopen64", "read", "pread",
        "pread64", "fread", "lseek", "fstat", "fstat64", "close"
    });
    counts.dynamic_link_import_hits = count_imports(imported, {
        "dlopen", "android_dlopen_ext", "dlsym", "dl_iterate_phdr", "dladdr"
    });

    const bool parser_axis = counts.elf_layout_hits >= 2;
    const bool relocation_axis = counts.relocation_hits >= 1;
    const bool dynamic_symbol_capability = counts.dynamic_link_import_hits >= 2;
    const bool dependency_symbol_axis =
        counts.dependency_symbol_hits >= 2 ||
        (parser_axis && relocation_axis && dynamic_symbol_capability);

    // A read-only ELF inspector commonly maps and unmaps a file.  Executable
    // loader semantics require an actual permission transition; munmap and
    // mremap remain observable support APIs but never complete this axis.
    const bool map_create = has_import(imported, {"mmap", "mmap64"});
    const bool map_permission_transition = has_import(imported, {"mprotect"});
    const bool mapping_axis = map_create && map_permission_transition;

    const bool file_open = has_import(imported, {
        "open", "open64", "openat", "fopen", "fopen64"
    });
    const bool file_read = has_import(imported, {
        "read", "pread", "pread64", "fread"
    });
    const bool file_source_axis = file_open && file_read;
    const bool constructor_axis = counts.constructor_hits >= 1;
    const bool functional_loader_identity =
        counts.explicit_loader_identity_hits >= 1 ||
        counts.linker_internal_hits >= 3;

    counts.independent_loader_axes =
        static_cast<std::size_t>(parser_axis) +
        static_cast<std::size_t>(relocation_axis) +
        static_cast<std::size_t>(dependency_symbol_axis) +
        static_cast<std::size_t>(mapping_axis) +
        static_cast<std::size_t>(constructor_axis) +
        static_cast<std::size_t>(file_source_axis);

    // API presence is deliberately insufficient.  A loader component needs
    // an ELF parser, relocation, dependency/symbol resolution, at least one
    // mapping/execution axis and four independent semantic axes in total.
    const bool core_loader_semantics =
        parser_axis && relocation_axis && dependency_symbol_axis;
    const bool execution_or_mapping = mapping_axis || constructor_axis;
    const bool implementation_semantics =
        functional_loader_identity || constructor_axis ||
        (mapping_axis && file_source_axis);
    result.loader_gate_passed =
        core_loader_semantics && execution_or_mapping &&
        counts.independent_loader_axes >= 4 && implementation_semantics;

    const bool explicit_protection_identity =
        counts.explicit_protection_identity_hits >= 1;
    const bool explicit_payload = counts.explicit_payload_identity_hits >= 1;
    counts.protection_axes =
        static_cast<std::size_t>(explicit_protection_identity) +
        static_cast<std::size_t>(explicit_payload) +
        static_cast<std::size_t>(context.protected_client_relationship);

    result.hook_alternative =
        context.known_hook_framework || exact_hook_basename ||
        hook_string_hits >= 2 ||
        (hook_string_hits >= 1 && counts.hook_primitive_hits >= 1);

    result.loader_score = clamp01(
        (parser_axis ? 0.20 : 0.0) +
        (relocation_axis ? 0.18 : 0.0) +
        (dependency_symbol_axis ? 0.18 : 0.0) +
        (mapping_axis ? 0.14 : 0.0) +
        (constructor_axis ? 0.12 : 0.0) +
        (file_source_axis ? 0.08 : 0.0) +
        (functional_loader_identity ? 0.07 : 0.0) +
        (counts.linker_internal_hits >= 2 ? 0.03 : 0.0));

    result.protection_score = clamp01(
        (explicit_protection_identity ? 0.40 : 0.0) +
        (explicit_payload ? 0.35 : 0.0) +
        (explicit_payload && context.high_entropy_payload ? 0.08 : 0.0) +
        (explicit_payload && context.packed_container ? 0.07 : 0.0) +
        (context.protected_client_relationship ? 0.45 : 0.0) +
        (result.loader_gate_passed ? 0.10 : 0.0));

    const bool protection_evidence = counts.protection_axes >= 1;
    bool protection_chain = result.loader_gate_passed && protection_evidence;

    // A known Hook framework can coexist with protection, but only when the
    // independent loader chain is stronger than ordinary ELF inspection and
    // patching: mapping plus at least five axes and constructor/loader identity.
    if (result.hook_alternative && protection_chain) {
        protection_chain =
            parser_axis && relocation_axis && dependency_symbol_axis &&
            mapping_axis && counts.independent_loader_axes >= 5 &&
            (constructor_axis || functional_loader_identity);
    }
    result.protection_gate_passed = protection_chain;

    const bool inspection_profile =
        parser_axis && (relocation_axis || dependency_symbol_axis) &&
        !result.loader_gate_passed;

    add_code(result, "GENERIC_LINKER_NOISE_IGNORED",
             counts.generic_linker_noise_hits != 0);
    add_code(result, "HOOK_FRAMEWORK_IDENTITY",
             counts.hook_identity_hits != 0);
    add_code(result, "HOOK_PATCHING_PRIMITIVES",
             counts.hook_primitive_hits != 0);
    add_code(result, "EXPLICIT_LOADER_IDENTITY",
             counts.explicit_loader_identity_hits != 0);
    add_code(result, "EXPLICIT_PROTECTION_IDENTITY",
             explicit_protection_identity);
    add_code(result, "EXPLICIT_PROTECTED_PAYLOAD", explicit_payload);
    add_code(result, "ELF_LAYOUT_PARSER", parser_axis);
    add_code(result, "RELOCATION_ENGINE", relocation_axis);
    add_code(result, "DEPENDENCY_SYMBOL_RESOLUTION", dependency_symbol_axis);
    add_code(result, "MEMORY_MAPPING_CAPABILITY", mapping_axis);
    add_code(result, "FILE_BACKED_SOURCE_CAPABILITY", file_source_axis);
    add_code(result, "CONSTRUCTOR_EXECUTION", constructor_axis);
    add_code(result, "DYNAMIC_LINK_API_CAPABILITY", dynamic_symbol_capability);
    add_code(result, "SECTIONLESS_ELF_NEUTRAL", context.sectionless);
    add_code(result, "PAYLOAD_CONTEXT_ONLY",
             !explicit_payload &&
             (context.high_entropy_payload || context.packed_container));
    add_code(result, "PROTECTION_RELATIONSHIP",
             context.protected_client_relationship);
    add_code(result, "ASSET_PATH_CONTEXT_ONLY", context.loaded_from_assets);
    add_code(result, "LOADER_AXIS_GATE_PASSED", result.loader_gate_passed);
    add_code(result, "HOOK_ALTERNATIVE_EXPLANATION", result.hook_alternative);
    add_code(result, "PROTECTION_CHAIN_PASSED",
             result.protection_gate_passed);
    add_code(result, "API_CAPABILITY_NOT_DECISIVE",
             !result.loader_gate_passed &&
             (mapping_axis || file_source_axis || dynamic_symbol_capability));
    add_code(result, "KNOWN_RUNTIME_ALTERNATIVE",
             context.known_runtime_framework);
    add_code(result, "PACKING_OBSCURES_LOADER",
             context.code_obscured_by_packing);

    if (result.protection_gate_passed) {
        result.outcome = Outcome::LIKELY_CUSTOM_LINKER_PROTECTION;
        result.confidence =
            counts.independent_loader_axes >= 5 && counts.protection_axes >= 1
                ? Confidence::HIGH
                : Confidence::MEDIUM;
    } else if (result.loader_gate_passed) {
        result.outcome = Outcome::CUSTOM_LOADER_COMPONENT;
        result.confidence =
            counts.independent_loader_axes >= 5 && functional_loader_identity
                ? Confidence::HIGH
                : Confidence::MEDIUM;
    } else if (result.hook_alternative) {
        result.outcome = Outcome::ELF_INSPECTION_OR_HOOK;
        result.confidence =
            context.known_hook_framework || exact_hook_basename ||
                    (hook_string_hits >= 1 &&
                     counts.hook_primitive_hits >= 1)
                ? Confidence::HIGH
                : Confidence::MEDIUM;
    } else if (context.code_obscured_by_packing) {
        result.outcome = Outcome::INCONCLUSIVE_PACKED;
        result.confidence = Confidence::UNKNOWN;
    } else if (inspection_profile) {
        result.outcome = Outcome::ELF_INSPECTION_OR_HOOK;
        result.confidence = Confidence::MEDIUM;
    } else {
        result.outcome = Outcome::NONE;
        result.confidence = Confidence::LOW;
    }

    return result;
}

}  // namespace obfuscan::custom_linker
