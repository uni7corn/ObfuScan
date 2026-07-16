#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace obfuscan::elf_dynamic {

// Program-header values are deliberately kept local to this small parser so
// callers do not need a platform elf.h (which is unavailable on MSVC).
inline constexpr uint32_t kPtLoad = 1;
inline constexpr uint32_t kPtDynamic = 2;
inline constexpr uint32_t kPfExecute = 0x1;

struct Segment {
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t file_offset = 0;
    uint64_t virtual_address = 0;
    uint64_t file_size = 0;
    uint64_t memory_size = 0;
};

struct FileSpan {
    size_t offset = 0;
    size_t available = 0;
};

enum class SymbolCountSource : uint8_t {
    None = 0,
    SysvHash,
    GnuHash,
    Relocations
};

struct DynamicSymbol {
    uint32_t index = 0;
    std::string name;
    uint64_t value = 0;
    uint64_t size = 0;
    uint16_t section_index = 0;
    uint8_t info = 0;
    uint8_t other = 0;

    bool undefined() const { return section_index == 0; }
};

struct ParseResult {
    bool dynamic_found = false;
    bool dynamic_terminated = false;
    bool valid = false;
    size_t dynamic_segment_count = 0;
    size_t dynamic_entry_count = 0;

    bool has_string_table = false;
    uint64_t string_table_va = 0;
    uint64_t string_table_size = 0;

    bool has_symbol_table = false;
    bool symbol_table_complete = false;
    uint64_t symbol_table_va = 0;
    uint64_t symbol_entry_size = 0;
    uint64_t declared_symbol_count = 0;
    SymbolCountSource symbol_count_source = SymbolCountSource::None;
    size_t rejected_symbol_names = 0;

    std::vector<std::string> needed_libraries;
    std::vector<std::string> imports;
    std::vector<DynamicSymbol> symbols;
    size_t exported_symbol_count = 0;

    bool has_init = false;
    uint64_t init_va = 0;
    bool has_fini = false;
    uint64_t fini_va = 0;

    bool has_init_array = false;
    uint64_t init_array_va = 0;
    uint64_t init_array_file_offset = 0;
    uint64_t init_array_size = 0;

    // File virtual addresses written by R_AARCH64_JUMP_SLOT relocations.
    // The vector is sorted and unique so callers can binary_search it.
    std::vector<uint64_t> jump_slot_vas;

    // Symbol indices observed in ordinary or PLT relocation tables. This is
    // also the bounded fallback when neither ELF nor GNU hash can provide the
    // complete dynamic-symbol count.
    std::vector<uint32_t> referenced_symbol_indices;

    // Malformed optional components are rejected independently. A valid
    // PT_DYNAMIC can therefore still return useful evidence plus warnings.
    std::vector<std::string> warnings;
};

// Maps a virtual-address range through a file-backed PT_LOAD. The returned
// availability never crosses the PT_LOAD's p_filesz or the input buffer.
bool va_to_file_span(uint64_t virtual_address,
                     uint64_t required_size,
                     const std::vector<Segment>& segments,
                     size_t input_size,
                     FileSpan& out);

// Parses already validated ELF64 little-endian AArch64 program-header views.
// The caller remains responsible for checking the ELF identity/machine fields.
ParseResult parse(const std::vector<uint8_t>& input,
                  const std::vector<Segment>& segments);

const char* symbol_count_source_name(SymbolCountSource source);

}  // namespace obfuscan::elf_dynamic
