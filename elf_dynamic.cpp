#include "elf_dynamic.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <unordered_set>
#include <utility>

namespace obfuscan::elf_dynamic {
namespace {

constexpr int64_t kDtNull = 0;
constexpr int64_t kDtNeeded = 1;
constexpr int64_t kDtPltRelSize = 2;
constexpr int64_t kDtPltGot = 3;
constexpr int64_t kDtHash = 4;
constexpr int64_t kDtStrTab = 5;
constexpr int64_t kDtSymTab = 6;
constexpr int64_t kDtRela = 7;
constexpr int64_t kDtRelaSize = 8;
constexpr int64_t kDtRelaEntry = 9;
constexpr int64_t kDtStrSize = 10;
constexpr int64_t kDtSymEntry = 11;
constexpr int64_t kDtInit = 12;
constexpr int64_t kDtFini = 13;
constexpr int64_t kDtRel = 17;
constexpr int64_t kDtRelSize = 18;
constexpr int64_t kDtRelEntry = 19;
constexpr int64_t kDtPltRel = 20;
constexpr int64_t kDtJumpRel = 23;
constexpr int64_t kDtInitArray = 25;
constexpr int64_t kDtInitArraySize = 27;
constexpr int64_t kDtGnuHash = 0x6ffffef5;

constexpr uint32_t kRAarch64JumpSlot = 1026;
constexpr uint64_t kMaxDynamicEntries = 65536;
constexpr uint64_t kMaxDynamicStringTable = 64ULL * 1024ULL * 1024ULL;
constexpr uint64_t kMaxNameLength = 64ULL * 1024ULL;
constexpr uint64_t kMaxDynamicSymbols = 1000000;
constexpr uint64_t kMaxHashBuckets = 1000000;
constexpr uint64_t kMaxRelocations = 1000000;
constexpr uint64_t kMaxInitArrayBytes = 16ULL * 1024ULL * 1024ULL;

#pragma pack(push, 1)
struct Elf64DynamicRaw {
    int64_t tag;
    uint64_t value;
};

struct Elf64SymbolRaw {
    uint32_t name;
    uint8_t info;
    uint8_t other;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
};

struct Elf64RelaRaw {
    uint64_t offset;
    uint64_t info;
    int64_t addend;
};

struct Elf64RelRaw {
    uint64_t offset;
    uint64_t info;
};
#pragma pack(pop)

static_assert(sizeof(Elf64DynamicRaw) == 16, "unexpected Elf64_Dyn layout");
static_assert(sizeof(Elf64SymbolRaw) == 24, "unexpected Elf64_Sym layout");
static_assert(sizeof(Elf64RelaRaw) == 24, "unexpected Elf64_Rela layout");
static_assert(sizeof(Elf64RelRaw) == 16, "unexpected Elf64_Rel layout");

struct DynamicTags {
    std::optional<uint64_t> plt_rel_size;
    std::optional<uint64_t> plt_got;
    std::optional<uint64_t> hash;
    std::optional<uint64_t> string_table;
    std::optional<uint64_t> symbol_table;
    std::optional<uint64_t> rela;
    std::optional<uint64_t> rela_size;
    std::optional<uint64_t> rela_entry;
    std::optional<uint64_t> string_size;
    std::optional<uint64_t> symbol_entry;
    std::optional<uint64_t> init;
    std::optional<uint64_t> fini;
    std::optional<uint64_t> rel;
    std::optional<uint64_t> rel_size;
    std::optional<uint64_t> rel_entry;
    std::optional<uint64_t> plt_rel;
    std::optional<uint64_t> jump_rel;
    std::optional<uint64_t> init_array;
    std::optional<uint64_t> init_array_size;
    std::optional<uint64_t> gnu_hash;
    std::vector<uint64_t> needed_offsets;
};

struct RelocationEvidence {
    std::set<uint32_t> symbol_indices;
    std::set<uint64_t> jump_slots;
};

bool checked_add(uint64_t lhs, uint64_t rhs, uint64_t& out) {
    if (rhs > std::numeric_limits<uint64_t>::max() - lhs) return false;
    out = lhs + rhs;
    return true;
}

bool checked_mul(uint64_t lhs, uint64_t rhs, uint64_t& out) {
    if (lhs != 0 && rhs > std::numeric_limits<uint64_t>::max() / lhs) return false;
    out = lhs * rhs;
    return true;
}

bool valid_file_range(uint64_t offset, uint64_t size, size_t input_size) {
    return offset <= input_size && size <= static_cast<uint64_t>(input_size) - offset;
}

template <typename T>
bool read_at(const std::vector<uint8_t>& input, size_t offset, T& value) {
    if (offset > input.size() || sizeof(T) > input.size() - offset) return false;
    std::memcpy(&value, input.data() + offset, sizeof(T));
    return true;
}

void add_warning(ParseResult& result, const std::string& warning) {
    if (std::find(result.warnings.begin(), result.warnings.end(), warning) ==
        result.warnings.end()) {
        result.warnings.push_back(warning);
    }
}

void set_once(std::optional<uint64_t>& target,
              uint64_t value,
              const char* tag_name,
              ParseResult& result) {
    if (!target.has_value()) {
        target = value;
    } else if (*target != value) {
        add_warning(result, std::string("conflicting ") + tag_name + " values");
    }
}

bool va_to_file_span_with_flags(uint64_t virtual_address,
                                uint64_t required_size,
                                uint32_t required_flags,
                                const std::vector<Segment>& segments,
                                size_t input_size,
                                FileSpan& out) {
    if (required_size > std::numeric_limits<uint64_t>::max() - virtual_address) {
        return false;
    }
    for (const auto& segment : segments) {
        if (segment.type != kPtLoad ||
            (segment.flags & required_flags) != required_flags ||
            virtual_address < segment.virtual_address) {
            continue;
        }

        const uint64_t delta = virtual_address - segment.virtual_address;
        if (segment.file_size > segment.memory_size ||
            delta >= segment.file_size || delta >= segment.memory_size) {
            continue;
        }

        uint64_t mapped_offset = 0;
        if (!checked_add(segment.file_offset, delta, mapped_offset) ||
            mapped_offset > input_size) {
            continue;
        }

        const uint64_t segment_available = std::min(segment.file_size - delta,
                                                    segment.memory_size - delta);
        const uint64_t input_available = static_cast<uint64_t>(input_size) - mapped_offset;
        const uint64_t available = std::min(segment_available, input_available);
        if (required_size > available ||
            available > std::numeric_limits<size_t>::max()) {
            continue;
        }

        out.offset = static_cast<size_t>(mapped_offset);
        out.available = static_cast<size_t>(available);
        return true;
    }
    return false;
}

bool read_string(const std::vector<uint8_t>& input,
                 const FileSpan& table,
                 uint64_t table_size,
                 uint64_t string_offset,
                 std::string& out) {
    if (table_size > table.available || string_offset >= table_size) return false;

    const uint64_t remaining = table_size - string_offset;
    const uint64_t scan_limit = std::min(remaining, kMaxNameLength + 1);
    const size_t begin = table.offset + static_cast<size_t>(string_offset);
    size_t length = 0;
    while (length < scan_limit && input[begin + length] != 0) ++length;
    if (length == scan_limit || length > kMaxNameLength) return false;

    out.assign(reinterpret_cast<const char*>(input.data() + begin), length);
    return true;
}

std::optional<uint64_t> sysv_hash_symbol_count(const std::vector<uint8_t>& input,
                                               const std::vector<Segment>& segments,
                                               uint64_t hash_va) {
    FileSpan header;
    if (!va_to_file_span(hash_va, 8, segments, input.size(), header)) return std::nullopt;

    uint32_t bucket_count = 0;
    uint32_t chain_count = 0;
    if (!read_at(input, header.offset, bucket_count) ||
        !read_at(input, header.offset + sizeof(uint32_t), chain_count) ||
        bucket_count == 0 || bucket_count > kMaxHashBuckets ||
        chain_count == 0 || chain_count > kMaxDynamicSymbols) {
        return std::nullopt;
    }

    uint64_t word_count = 0;
    if (!checked_add(2, bucket_count, word_count) ||
        !checked_add(word_count, chain_count, word_count)) {
        return std::nullopt;
    }
    uint64_t byte_count = 0;
    if (!checked_mul(word_count, sizeof(uint32_t), byte_count)) return std::nullopt;

    FileSpan full_hash;
    if (!va_to_file_span(hash_va, byte_count, segments, input.size(), full_hash)) {
        return std::nullopt;
    }
    return chain_count;
}

std::optional<uint64_t> gnu_hash_symbol_count(const std::vector<uint8_t>& input,
                                              const std::vector<Segment>& segments,
                                              uint64_t hash_va) {
    FileSpan header;
    if (!va_to_file_span(hash_va, 16, segments, input.size(), header)) return std::nullopt;

    uint32_t bucket_count = 0;
    uint32_t symbol_offset = 0;
    uint32_t bloom_size = 0;
    uint32_t bloom_shift = 0;
    if (!read_at(input, header.offset, bucket_count) ||
        !read_at(input, header.offset + 4, symbol_offset) ||
        !read_at(input, header.offset + 8, bloom_size) ||
        !read_at(input, header.offset + 12, bloom_shift)) {
        return std::nullopt;
    }
    (void)bloom_shift;

    if (bucket_count == 0 || bucket_count > kMaxHashBuckets ||
        bloom_size == 0 || bloom_size > kMaxHashBuckets ||
        symbol_offset > kMaxDynamicSymbols) {
        return std::nullopt;
    }

    uint64_t bloom_bytes = 0;
    uint64_t bucket_bytes = 0;
    uint64_t bucket_offset = 0;
    uint64_t chain_offset = 0;
    if (!checked_mul(bloom_size, uint64_t{8}, bloom_bytes) ||
        !checked_mul(bucket_count, uint64_t{4}, bucket_bytes) ||
        !checked_add(16, bloom_bytes, bucket_offset) ||
        !checked_add(bucket_offset, bucket_bytes, chain_offset)) {
        return std::nullopt;
    }

    FileSpan prefix;
    if (!va_to_file_span(hash_va, chain_offset, segments, input.size(), prefix)) {
        return std::nullopt;
    }

    uint32_t maximum_bucket = 0;
    const size_t buckets_file_offset = prefix.offset + static_cast<size_t>(bucket_offset);
    for (uint32_t i = 0; i < bucket_count; ++i) {
        uint32_t bucket = 0;
        if (!read_at(input, buckets_file_offset + static_cast<size_t>(i) * 4, bucket)) {
            return std::nullopt;
        }
        if (bucket == 0) continue;
        if (bucket < symbol_offset || bucket >= kMaxDynamicSymbols) return std::nullopt;
        maximum_bucket = std::max(maximum_bucket, bucket);
    }

    if (maximum_bucket == 0) return symbol_offset;

    const uint64_t chain_index = uint64_t{maximum_bucket} - symbol_offset;
    uint64_t chain_index_bytes = 0;
    uint64_t chain_va = 0;
    if (!checked_mul(chain_index, uint64_t{4}, chain_index_bytes) ||
        !checked_add(hash_va, chain_offset, chain_va) ||
        !checked_add(chain_va, chain_index_bytes, chain_va)) {
        return std::nullopt;
    }

    FileSpan chains;
    if (!va_to_file_span(chain_va, 4, segments, input.size(), chains)) return std::nullopt;

    const uint64_t maximum_steps = std::min<uint64_t>(
        chains.available / sizeof(uint32_t),
        kMaxDynamicSymbols - maximum_bucket);
    for (uint64_t step = 0; step < maximum_steps; ++step) {
        uint32_t chain = 0;
        if (!read_at(input, chains.offset + static_cast<size_t>(step) * 4, chain)) {
            return std::nullopt;
        }
        if ((chain & 1U) != 0) return uint64_t{maximum_bucket} + step + 1;
    }
    return std::nullopt;
}

void record_relocation(uint64_t offset,
                       uint64_t info,
                       RelocationEvidence& evidence) {
    const uint64_t symbol = info >> 32U;
    const uint32_t type = static_cast<uint32_t>(info);
    if (symbol < kMaxDynamicSymbols && symbol <= std::numeric_limits<uint32_t>::max()) {
        evidence.symbol_indices.insert(static_cast<uint32_t>(symbol));
    }
    if (type == kRAarch64JumpSlot) evidence.jump_slots.insert(offset);
}

void parse_rela_table(const std::vector<uint8_t>& input,
                      const std::vector<Segment>& segments,
                      uint64_t table_va,
                      uint64_t table_size,
                      uint64_t entry_size,
                      const char* label,
                      RelocationEvidence& evidence,
                      ParseResult& result) {
    if (entry_size != sizeof(Elf64RelaRaw) ||
        table_size % entry_size != 0 ||
        table_size / entry_size > kMaxRelocations) {
        add_warning(result, std::string("invalid ") + label + " layout");
        return;
    }
    if (table_size == 0) return;

    FileSpan table;
    if (!va_to_file_span(table_va, table_size, segments, input.size(), table)) {
        add_warning(result, std::string("unmapped ") + label);
        return;
    }

    const uint64_t count = table_size / entry_size;
    for (uint64_t index = 0; index < count; ++index) {
        Elf64RelaRaw relocation{};
        const size_t offset = table.offset + static_cast<size_t>(index * entry_size);
        if (!read_at(input, offset, relocation)) break;
        record_relocation(relocation.offset, relocation.info, evidence);
    }
}

void parse_rel_table(const std::vector<uint8_t>& input,
                     const std::vector<Segment>& segments,
                     uint64_t table_va,
                     uint64_t table_size,
                     uint64_t entry_size,
                     const char* label,
                     RelocationEvidence& evidence,
                     ParseResult& result) {
    if (entry_size != sizeof(Elf64RelRaw) ||
        table_size % entry_size != 0 ||
        table_size / entry_size > kMaxRelocations) {
        add_warning(result, std::string("invalid ") + label + " layout");
        return;
    }
    if (table_size == 0) return;

    FileSpan table;
    if (!va_to_file_span(table_va, table_size, segments, input.size(), table)) {
        add_warning(result, std::string("unmapped ") + label);
        return;
    }

    const uint64_t count = table_size / entry_size;
    for (uint64_t index = 0; index < count; ++index) {
        Elf64RelRaw relocation{};
        const size_t offset = table.offset + static_cast<size_t>(index * entry_size);
        if (!read_at(input, offset, relocation)) break;
        record_relocation(relocation.offset, relocation.info, evidence);
    }
}

}  // namespace

bool va_to_file_span(uint64_t virtual_address,
                     uint64_t required_size,
                     const std::vector<Segment>& segments,
                     size_t input_size,
                     FileSpan& out) {
    return va_to_file_span_with_flags(virtual_address, required_size, 0,
                                      segments, input_size, out);
}

ParseResult parse(const std::vector<uint8_t>& input,
                  const std::vector<Segment>& segments) {
    ParseResult result;
    DynamicTags tags;

    for (const auto& segment : segments) {
        if (segment.type != kPtDynamic) continue;
        result.dynamic_found = true;
        result.dynamic_segment_count++;

        if (!valid_file_range(segment.file_offset, segment.file_size, input.size())) {
            add_warning(result, "PT_DYNAMIC is outside the input file");
            continue;
        }

        if (segment.file_size % sizeof(Elf64DynamicRaw) != 0) {
            add_warning(result, "PT_DYNAMIC size is not entry-aligned");
        }
        const uint64_t available_entries = segment.file_size / sizeof(Elf64DynamicRaw);
        const uint64_t entry_limit = std::min(available_entries, kMaxDynamicEntries);
        bool terminated = false;
        DynamicTags candidate_tags;

        for (uint64_t index = 0; index < entry_limit; ++index) {
            Elf64DynamicRaw entry{};
            const uint64_t relative = index * sizeof(Elf64DynamicRaw);
            const size_t file_offset = static_cast<size_t>(segment.file_offset + relative);
            if (!read_at(input, file_offset, entry)) break;
            result.dynamic_entry_count++;

            if (entry.tag == kDtNull) {
                terminated = true;
                break;
            }

            switch (entry.tag) {
                case kDtNeeded: candidate_tags.needed_offsets.push_back(entry.value); break;
                case kDtPltRelSize: set_once(candidate_tags.plt_rel_size, entry.value, "DT_PLTRELSZ", result); break;
                case kDtPltGot: set_once(candidate_tags.plt_got, entry.value, "DT_PLTGOT", result); break;
                case kDtHash: set_once(candidate_tags.hash, entry.value, "DT_HASH", result); break;
                case kDtStrTab: set_once(candidate_tags.string_table, entry.value, "DT_STRTAB", result); break;
                case kDtSymTab: set_once(candidate_tags.symbol_table, entry.value, "DT_SYMTAB", result); break;
                case kDtRela: set_once(candidate_tags.rela, entry.value, "DT_RELA", result); break;
                case kDtRelaSize: set_once(candidate_tags.rela_size, entry.value, "DT_RELASZ", result); break;
                case kDtRelaEntry: set_once(candidate_tags.rela_entry, entry.value, "DT_RELAENT", result); break;
                case kDtStrSize: set_once(candidate_tags.string_size, entry.value, "DT_STRSZ", result); break;
                case kDtSymEntry: set_once(candidate_tags.symbol_entry, entry.value, "DT_SYMENT", result); break;
                case kDtInit: set_once(candidate_tags.init, entry.value, "DT_INIT", result); break;
                case kDtFini: set_once(candidate_tags.fini, entry.value, "DT_FINI", result); break;
                case kDtRel: set_once(candidate_tags.rel, entry.value, "DT_REL", result); break;
                case kDtRelSize: set_once(candidate_tags.rel_size, entry.value, "DT_RELSZ", result); break;
                case kDtRelEntry: set_once(candidate_tags.rel_entry, entry.value, "DT_RELENT", result); break;
                case kDtPltRel: set_once(candidate_tags.plt_rel, entry.value, "DT_PLTREL", result); break;
                case kDtJumpRel: set_once(candidate_tags.jump_rel, entry.value, "DT_JMPREL", result); break;
                case kDtInitArray: set_once(candidate_tags.init_array, entry.value, "DT_INIT_ARRAY", result); break;
                case kDtInitArraySize: set_once(candidate_tags.init_array_size, entry.value, "DT_INIT_ARRAYSZ", result); break;
                case kDtGnuHash: set_once(candidate_tags.gnu_hash, entry.value, "DT_GNU_HASH", result); break;
                default: break;
            }
        }

        if (!terminated) {
            add_warning(result, "PT_DYNAMIC has no bounded DT_NULL terminator");
        } else if (!result.dynamic_terminated) {
            tags = std::move(candidate_tags);
            result.dynamic_terminated = true;
        } else {
            add_warning(result, "multiple terminated PT_DYNAMIC segments; using the first");
        }
    }

    result.valid = result.dynamic_found && result.dynamic_terminated;
    if (!result.valid) return result;

    FileSpan string_table;
    if (tags.string_table && tags.string_size &&
        *tags.string_size > 0 && *tags.string_size <= kMaxDynamicStringTable &&
        va_to_file_span(*tags.string_table, *tags.string_size,
                        segments, input.size(), string_table)) {
        result.has_string_table = true;
        result.string_table_va = *tags.string_table;
        result.string_table_size = *tags.string_size;

        std::unordered_set<std::string> seen_needed;
        for (uint64_t string_offset : tags.needed_offsets) {
            std::string name;
            if (!read_string(input, string_table, *tags.string_size,
                             string_offset, name) || name.empty()) {
                add_warning(result, "invalid DT_NEEDED string offset");
                continue;
            }
            if (seen_needed.insert(name).second) {
                result.needed_libraries.push_back(std::move(name));
            }
        }
    } else if (tags.string_table || tags.string_size) {
        add_warning(result, "invalid dynamic string table");
    }

    RelocationEvidence relocations;
    if (tags.rela && tags.rela_size) {
        parse_rela_table(input, segments, *tags.rela, *tags.rela_size,
                         tags.rela_entry.value_or(sizeof(Elf64RelaRaw)),
                         "DT_RELA", relocations, result);
    } else if (tags.rela || tags.rela_size) {
        add_warning(result, "incomplete DT_RELA metadata");
    }
    if (tags.rel && tags.rel_size) {
        parse_rel_table(input, segments, *tags.rel, *tags.rel_size,
                        tags.rel_entry.value_or(sizeof(Elf64RelRaw)),
                        "DT_REL", relocations, result);
    } else if (tags.rel || tags.rel_size) {
        add_warning(result, "incomplete DT_REL metadata");
    }

    if (tags.jump_rel && tags.plt_rel_size) {
        uint64_t relocation_kind = kDtRela;
        if (tags.plt_rel) {
            relocation_kind = *tags.plt_rel;
        } else {
            add_warning(result, "missing DT_PLTREL; assuming AArch64 RELA");
        }

        if (relocation_kind == static_cast<uint64_t>(kDtRela)) {
            parse_rela_table(input, segments, *tags.jump_rel, *tags.plt_rel_size,
                             tags.rela_entry.value_or(sizeof(Elf64RelaRaw)),
                             "DT_JMPREL(RELA)", relocations, result);
        } else if (relocation_kind == static_cast<uint64_t>(kDtRel)) {
            parse_rel_table(input, segments, *tags.jump_rel, *tags.plt_rel_size,
                            tags.rel_entry.value_or(sizeof(Elf64RelRaw)),
                            "DT_JMPREL(REL)", relocations, result);
        } else {
            add_warning(result, "unsupported DT_PLTREL value");
        }
    } else if (tags.jump_rel || tags.plt_rel_size) {
        add_warning(result, "incomplete DT_JMPREL metadata");
    }

    result.referenced_symbol_indices.assign(relocations.symbol_indices.begin(),
                                            relocations.symbol_indices.end());
    result.jump_slot_vas.assign(relocations.jump_slots.begin(),
                                relocations.jump_slots.end());

    std::optional<uint64_t> symbol_count;
    if (tags.hash) {
        symbol_count = sysv_hash_symbol_count(input, segments, *tags.hash);
        if (symbol_count) {
            result.symbol_count_source = SymbolCountSource::SysvHash;
        } else {
            add_warning(result, "invalid DT_HASH table");
        }
    }
    if (!symbol_count && tags.gnu_hash) {
        symbol_count = gnu_hash_symbol_count(input, segments, *tags.gnu_hash);
        if (symbol_count) {
            result.symbol_count_source = SymbolCountSource::GnuHash;
        } else {
            add_warning(result, "invalid DT_GNU_HASH table");
        }
    }

    const uint64_t symbol_entry_size = tags.symbol_entry.value_or(sizeof(Elf64SymbolRaw));
    result.symbol_entry_size = symbol_entry_size;
    if (tags.symbol_table) result.symbol_table_va = *tags.symbol_table;

    FileSpan symbol_probe;
    if (tags.symbol_table && symbol_entry_size == sizeof(Elf64SymbolRaw) &&
        va_to_file_span(*tags.symbol_table, sizeof(Elf64SymbolRaw),
                        segments, input.size(), symbol_probe)) {
        result.has_symbol_table = true;
    } else if (tags.symbol_table || tags.symbol_entry) {
        add_warning(result, "invalid dynamic symbol table metadata");
    }

    std::vector<uint32_t> indices;
    if (result.has_symbol_table && symbol_count && *symbol_count <= kMaxDynamicSymbols) {
        uint64_t symbol_bytes = 0;
        FileSpan full_symbols;
        if (checked_mul(*symbol_count, symbol_entry_size, symbol_bytes) &&
            (*symbol_count == 0 ||
             va_to_file_span(*tags.symbol_table, symbol_bytes,
                             segments, input.size(), full_symbols))) {
            result.symbol_table_complete = true;
            result.declared_symbol_count = *symbol_count;
            indices.reserve(static_cast<size_t>(*symbol_count));
            for (uint64_t index = 0; index < *symbol_count; ++index) {
                indices.push_back(static_cast<uint32_t>(index));
            }
        } else {
            add_warning(result, "dynamic symbol table exceeds its PT_LOAD");
        }
    }

    if (!result.symbol_table_complete && result.has_symbol_table &&
        !result.referenced_symbol_indices.empty()) {
        result.symbol_count_source = SymbolCountSource::Relocations;
        indices = result.referenced_symbol_indices;
        result.declared_symbol_count = uint64_t{indices.back()} + 1;
    }

    std::unordered_set<std::string> seen_imports;
    for (uint32_t index : indices) {
        uint64_t relative = 0;
        uint64_t symbol_va = 0;
        if (!checked_mul(index, symbol_entry_size, relative) ||
            !checked_add(*tags.symbol_table, relative, symbol_va)) {
            continue;
        }

        FileSpan symbol_span;
        if (!va_to_file_span(symbol_va, sizeof(Elf64SymbolRaw),
                             segments, input.size(), symbol_span)) {
            continue;
        }

        Elf64SymbolRaw raw{};
        if (!read_at(input, symbol_span.offset, raw)) continue;

        std::string name;
        if (!result.has_string_table ||
            !read_string(input, string_table, result.string_table_size,
                         raw.name, name)) {
            if (raw.name != 0) result.rejected_symbol_names++;
            continue;
        }
        if (name.empty()) continue;

        DynamicSymbol symbol;
        symbol.index = index;
        symbol.name = name;
        symbol.value = raw.value;
        symbol.size = raw.size;
        symbol.section_index = raw.section_index;
        symbol.info = raw.info;
        symbol.other = raw.other;
        result.symbols.push_back(std::move(symbol));

        if (raw.section_index == 0) {
            if (seen_imports.insert(name).second) result.imports.push_back(std::move(name));
        } else {
            result.exported_symbol_count++;
        }
    }

    if (tags.init && *tags.init != 0) {
        FileSpan init_span;
        if (va_to_file_span_with_flags(*tags.init, 4, kPfExecute,
                                       segments, input.size(), init_span)) {
            result.has_init = true;
            result.init_va = *tags.init;
        } else {
            add_warning(result, "DT_INIT does not map to file-backed executable code");
        }
    }
    if (tags.fini && *tags.fini != 0) {
        FileSpan fini_span;
        if (va_to_file_span_with_flags(*tags.fini, 4, kPfExecute,
                                       segments, input.size(), fini_span)) {
            result.has_fini = true;
            result.fini_va = *tags.fini;
        } else {
            add_warning(result, "DT_FINI does not map to file-backed executable code");
        }
    }

    if (tags.init_array && tags.init_array_size) {
        FileSpan array_span;
        if (*tags.init_array_size > 0 &&
            *tags.init_array_size <= kMaxInitArrayBytes &&
            *tags.init_array_size % sizeof(uint64_t) == 0 &&
            va_to_file_span(*tags.init_array, *tags.init_array_size,
                            segments, input.size(), array_span)) {
            result.has_init_array = true;
            result.init_array_va = *tags.init_array;
            result.init_array_file_offset = array_span.offset;
            result.init_array_size = *tags.init_array_size;
        } else {
            add_warning(result, "invalid DT_INIT_ARRAY range");
        }
    } else if (tags.init_array || tags.init_array_size) {
        add_warning(result, "incomplete DT_INIT_ARRAY metadata");
    }

    return result;
}

const char* symbol_count_source_name(SymbolCountSource source) {
    switch (source) {
        case SymbolCountSource::SysvHash: return "SYSV_HASH";
        case SymbolCountSource::GnuHash: return "GNU_HASH";
        case SymbolCountSource::Relocations: return "RELOCATIONS";
        case SymbolCountSource::None:
        default: return "NONE";
    }
}

}  // namespace obfuscan::elf_dynamic
