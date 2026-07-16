#include "elf_dynamic.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using obfuscan::elf_dynamic::ParseResult;
using obfuscan::elf_dynamic::Segment;
using obfuscan::elf_dynamic::SymbolCountSource;

constexpr uint64_t kLoadVa = 0x1000;
constexpr size_t kDynamicOffset = 0x100;

constexpr int64_t kDtNull = 0;
constexpr int64_t kDtNeeded = 1;
constexpr int64_t kDtPltRelSize = 2;
constexpr int64_t kDtHash = 4;
constexpr int64_t kDtStrTab = 5;
constexpr int64_t kDtSymTab = 6;
constexpr int64_t kDtRela = 7;
constexpr int64_t kDtRelaSize = 8;
constexpr int64_t kDtRelaEntry = 9;
constexpr int64_t kDtStrSize = 10;
constexpr int64_t kDtSymEntry = 11;
constexpr int64_t kDtInit = 12;
constexpr int64_t kDtPltRel = 20;
constexpr int64_t kDtJumpRel = 23;
constexpr int64_t kDtInitArray = 25;
constexpr int64_t kDtInitArraySize = 27;
constexpr int64_t kDtGnuHash = 0x6ffffef5;

constexpr uint32_t kRAarch64JumpSlot = 1026;
constexpr uint32_t kRAarch64Relative = 1027;

#pragma pack(push, 1)
struct DynamicRaw {
    int64_t tag;
    uint64_t value;
};

struct SymbolRaw {
    uint32_t name;
    uint8_t info;
    uint8_t other;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
};

struct RelaRaw {
    uint64_t offset;
    uint64_t info;
    int64_t addend;
};
#pragma pack(pop)

static_assert(sizeof(DynamicRaw) == 16, "bad test dynamic layout");
static_assert(sizeof(SymbolRaw) == 24, "bad test symbol layout");
static_assert(sizeof(RelaRaw) == 24, "bad test relocation layout");

void expect(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename T>
void put(std::vector<uint8_t>& bytes, size_t offset, const T& value) {
    expect(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset,
           "test fixture write out of range");
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

uint64_t va(size_t file_offset) {
    return kLoadVa + file_offset;
}

uint32_t append_string(std::vector<uint8_t>& table, const std::string& value) {
    const uint32_t offset = static_cast<uint32_t>(table.size());
    table.insert(table.end(), value.begin(), value.end());
    table.push_back(0);
    return offset;
}

struct Fixture {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(0x1000, 0);
    std::vector<DynamicRaw> dynamic;

    void add(int64_t tag, uint64_t value) {
        dynamic.push_back(DynamicRaw{tag, value});
    }

    std::vector<Segment> finish(bool include_null = true) {
        if (include_null) add(kDtNull, 0);
        for (size_t i = 0; i < dynamic.size(); ++i) {
            put(bytes, kDynamicOffset + i * sizeof(DynamicRaw), dynamic[i]);
        }

        Segment load;
        load.type = obfuscan::elf_dynamic::kPtLoad;
        load.flags = obfuscan::elf_dynamic::kPfExecute | 0x4;
        load.file_offset = 0;
        load.virtual_address = kLoadVa;
        load.file_size = bytes.size();
        load.memory_size = bytes.size();

        Segment dyn;
        dyn.type = obfuscan::elf_dynamic::kPtDynamic;
        dyn.flags = 0x6;
        dyn.file_offset = kDynamicOffset;
        dyn.virtual_address = va(kDynamicOffset);
        dyn.file_size = dynamic.size() * sizeof(DynamicRaw);
        dyn.memory_size = dyn.file_size;
        return {load, dyn};
    }
};

bool has_string(const std::vector<std::string>& values, const std::string& wanted) {
    return std::find(values.begin(), values.end(), wanted) != values.end();
}

void write_symbols(std::vector<uint8_t>& bytes,
                   size_t symbol_offset,
                   uint32_t import_name,
                   uint32_t export_name) {
    put(bytes, symbol_offset, SymbolRaw{});

    SymbolRaw imported{};
    imported.name = import_name;
    imported.info = 0x12;
    imported.section_index = 0;
    put(bytes, symbol_offset + sizeof(SymbolRaw), imported);

    SymbolRaw exported{};
    exported.name = export_name;
    exported.info = 0x12;
    exported.section_index = 1;
    exported.value = va(0x800);
    exported.size = 32;
    put(bytes, symbol_offset + 2 * sizeof(SymbolRaw), exported);
}

void test_sysv_hash_needed_init_and_jump_slots() {
    Fixture fixture;
    constexpr size_t string_offset = 0x300;
    constexpr size_t symbol_offset = 0x400;
    constexpr size_t hash_offset = 0x500;
    constexpr size_t init_array_offset = 0x600;
    constexpr size_t jump_relocation_offset = 0x700;

    std::vector<uint8_t> strings(1, 0);
    const uint32_t needed_name = append_string(strings, "libc.so");
    const uint32_t import_name = append_string(strings, "mmap");
    const uint32_t export_name = append_string(strings, "exported_entry");
    std::memcpy(fixture.bytes.data() + string_offset, strings.data(), strings.size());
    write_symbols(fixture.bytes, symbol_offset, import_name, export_name);

    const uint32_t sysv_hash[] = {1, 3, 0, 0, 0, 0};
    std::memcpy(fixture.bytes.data() + hash_offset, sysv_hash, sizeof(sysv_hash));

    RelaRaw jump{};
    jump.offset = va(0x900);
    jump.info = (uint64_t{1} << 32U) | kRAarch64JumpSlot;
    put(fixture.bytes, jump_relocation_offset, jump);

    fixture.add(kDtNeeded, needed_name);
    fixture.add(kDtStrTab, va(string_offset));
    fixture.add(kDtStrSize, strings.size());
    fixture.add(kDtSymTab, va(symbol_offset));
    fixture.add(kDtSymEntry, sizeof(SymbolRaw));
    fixture.add(kDtHash, va(hash_offset));
    // A valid SysV hash must win without consulting this unusable GNU hash.
    fixture.add(kDtGnuHash, std::numeric_limits<uint64_t>::max() - 32);
    fixture.add(kDtInit, va(0x800));
    fixture.add(kDtInitArray, va(init_array_offset));
    fixture.add(kDtInitArraySize, 16);
    fixture.add(kDtJumpRel, va(jump_relocation_offset));
    fixture.add(kDtPltRelSize, sizeof(RelaRaw));
    fixture.add(kDtPltRel, kDtRela);
    fixture.add(kDtRelaEntry, sizeof(RelaRaw));

    const ParseResult result = obfuscan::elf_dynamic::parse(fixture.bytes, fixture.finish());
    expect(result.valid, "SysV fixture PT_DYNAMIC should be valid");
    expect(result.has_string_table, "SysV fixture should recover DT_STRTAB");
    expect(result.has_symbol_table && result.symbol_table_complete,
           "SysV fixture should recover the complete dynsym");
    expect(result.symbol_count_source == SymbolCountSource::SysvHash,
           "DT_HASH must take priority over DT_GNU_HASH");
    expect(result.declared_symbol_count == 3, "SysV nchain should define dynsym count");
    expect(has_string(result.needed_libraries, "libc.so"), "DT_NEEDED name missing");
    expect(has_string(result.imports, "mmap"), "undefined dynsym import missing");
    expect(result.exported_symbol_count == 1, "defined dynsym export missing");
    expect(result.has_init && result.init_va == va(0x800), "DT_INIT metadata missing");
    expect(result.has_init_array &&
           result.init_array_file_offset == init_array_offset &&
           result.init_array_size == 16,
           "DT_INIT_ARRAY metadata missing");
    expect(result.jump_slot_vas.size() == 1 && result.jump_slot_vas[0] == va(0x900),
           "R_AARCH64_JUMP_SLOT target missing");
}

void test_gnu_hash_count() {
    Fixture fixture;
    constexpr size_t string_offset = 0x300;
    constexpr size_t symbol_offset = 0x400;
    constexpr size_t hash_offset = 0x500;

    std::vector<uint8_t> strings(1, 0);
    const uint32_t import_name = append_string(strings, "lua_pcall");
    const uint32_t export_name = append_string(strings, "module_init");
    std::memcpy(fixture.bytes.data() + string_offset, strings.data(), strings.size());
    write_symbols(fixture.bytes, symbol_offset, import_name, export_name);

    const uint32_t header[] = {1, 1, 1, 5};
    std::memcpy(fixture.bytes.data() + hash_offset, header, sizeof(header));
    const uint64_t bloom = 0;
    put(fixture.bytes, hash_offset + 16, bloom);
    const uint32_t bucket = 1;
    put(fixture.bytes, hash_offset + 24, bucket);
    const uint32_t first_chain = 0x100;
    const uint32_t terminating_chain = 0x101;
    put(fixture.bytes, hash_offset + 28, first_chain);
    put(fixture.bytes, hash_offset + 32, terminating_chain);

    fixture.add(kDtStrTab, va(string_offset));
    fixture.add(kDtStrSize, strings.size());
    fixture.add(kDtSymTab, va(symbol_offset));
    fixture.add(kDtSymEntry, sizeof(SymbolRaw));
    fixture.add(kDtHash, std::numeric_limits<uint64_t>::max() - 32);
    fixture.add(kDtGnuHash, va(hash_offset));

    const ParseResult result = obfuscan::elf_dynamic::parse(fixture.bytes, fixture.finish());
    expect(result.valid, "GNU hash fixture should be valid");
    expect(result.symbol_count_source == SymbolCountSource::GnuHash,
           "GNU hash source was not selected");
    expect(result.symbol_table_complete && result.declared_symbol_count == 3,
           "GNU chain termination should recover three dynsyms");
    expect(has_string(result.imports, "lua_pcall"), "GNU-hash import missing");
    expect(result.exported_symbol_count == 1, "GNU-hash export missing");
}

void test_relocation_symbol_fallback() {
    Fixture fixture;
    constexpr size_t string_offset = 0x300;
    constexpr size_t symbol_offset = 0x400;
    constexpr size_t rela_offset = 0x500;
    constexpr size_t jump_offset = 0x540;

    std::vector<uint8_t> strings(1, 0);
    const uint32_t import_name = append_string(strings, "dlsym");
    const uint32_t export_name = append_string(strings, "protected_entry");
    std::memcpy(fixture.bytes.data() + string_offset, strings.data(), strings.size());
    write_symbols(fixture.bytes, symbol_offset, import_name, export_name);

    RelaRaw ordinary{};
    ordinary.offset = va(0x920);
    ordinary.info = (uint64_t{2} << 32U) | kRAarch64Relative;
    put(fixture.bytes, rela_offset, ordinary);

    RelaRaw jump{};
    jump.offset = va(0x928);
    jump.info = (uint64_t{1} << 32U) | kRAarch64JumpSlot;
    put(fixture.bytes, jump_offset, jump);

    fixture.add(kDtStrTab, va(string_offset));
    fixture.add(kDtStrSize, strings.size());
    fixture.add(kDtSymTab, va(symbol_offset));
    fixture.add(kDtSymEntry, sizeof(SymbolRaw));
    fixture.add(kDtRela, va(rela_offset));
    fixture.add(kDtRelaSize, sizeof(RelaRaw));
    fixture.add(kDtRelaEntry, sizeof(RelaRaw));
    fixture.add(kDtJumpRel, va(jump_offset));
    fixture.add(kDtPltRelSize, sizeof(RelaRaw));
    fixture.add(kDtPltRel, kDtRela);

    const ParseResult result = obfuscan::elf_dynamic::parse(fixture.bytes, fixture.finish());
    expect(result.valid, "relocation fallback fixture should be valid");
    expect(result.has_symbol_table && !result.symbol_table_complete,
           "relocation fallback must be explicitly partial");
    expect(result.symbol_count_source == SymbolCountSource::Relocations,
           "relocation fallback source missing");
    expect(result.referenced_symbol_indices == std::vector<uint32_t>({1, 2}),
           "relocation symbol indices should be sorted and unique");
    expect(has_string(result.imports, "dlsym"), "relocation import missing");
    expect(result.exported_symbol_count == 1, "referenced export missing");
    expect(result.jump_slot_vas == std::vector<uint64_t>({va(0x928)}),
           "relocation fallback JUMP_SLOT missing");
}

void test_malformed_bounds_and_termination() {
    std::vector<uint8_t> bytes(64, 0);
    Segment wrapping;
    wrapping.type = obfuscan::elf_dynamic::kPtLoad;
    wrapping.file_offset = 0;
    wrapping.virtual_address = std::numeric_limits<uint64_t>::max() - 8;
    wrapping.file_size = 16;
    wrapping.memory_size = 16;

    obfuscan::elf_dynamic::FileSpan span;
    expect(!obfuscan::elf_dynamic::va_to_file_span(
               std::numeric_limits<uint64_t>::max() - 4, 8,
               std::vector<Segment>{wrapping}, bytes.size(), span),
           "VA range wrapping UINT64_MAX must be rejected");

    Fixture unterminated;
    unterminated.add(kDtStrTab, va(0x300));
    const ParseResult no_null = obfuscan::elf_dynamic::parse(
        unterminated.bytes, unterminated.finish(false));
    expect(no_null.dynamic_found && !no_null.dynamic_terminated && !no_null.valid,
           "unterminated PT_DYNAMIC must be invalid");

    Fixture oversized_strings;
    oversized_strings.add(kDtStrTab, va(0x300));
    oversized_strings.add(kDtStrSize, 128ULL * 1024ULL * 1024ULL);
    const ParseResult oversized = obfuscan::elf_dynamic::parse(
        oversized_strings.bytes, oversized_strings.finish());
    expect(oversized.valid && !oversized.has_string_table && !oversized.warnings.empty(),
           "oversized DT_STRTAB must be rejected without invalidating PT_DYNAMIC");

    Fixture unterminated_gnu_chain;
    constexpr size_t bad_hash_offset = 0x500;
    const uint32_t bad_header[] = {1, 1, 1, 5};
    std::memcpy(unterminated_gnu_chain.bytes.data() + bad_hash_offset,
                bad_header, sizeof(bad_header));
    const uint64_t empty_bloom = 0;
    put(unterminated_gnu_chain.bytes, bad_hash_offset + 16, empty_bloom);
    const uint32_t first_symbol = 1;
    put(unterminated_gnu_chain.bytes, bad_hash_offset + 24, first_symbol);
    // The remaining zero-filled chain never sets its low termination bit.
    unterminated_gnu_chain.add(kDtGnuHash, va(bad_hash_offset));
    const ParseResult bad_gnu = obfuscan::elf_dynamic::parse(
        unterminated_gnu_chain.bytes, unterminated_gnu_chain.finish());
    expect(bad_gnu.valid && bad_gnu.symbol_count_source == SymbolCountSource::None &&
           !bad_gnu.warnings.empty(),
           "unterminated GNU hash chain must be rejected within the mapped span");
}

}  // namespace

int main() {
    try {
        test_sysv_hash_needed_init_and_jump_slots();
        test_gnu_hash_count();
        test_relocation_symbol_fallback();
        test_malformed_bounds_and_termination();
        std::cout << "elf_dynamic_tests: all tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "elf_dynamic_tests: " << error.what() << '\n';
        return 1;
    }
}
