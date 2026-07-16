#include "vmp_detector.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr size_t kLookbackInstructions = 32;
constexpr size_t kLookaheadInstructions = 8;
// Avoid premature sampling for ordinary large runtimes. The old 24k cap made
// a 4.5 MiB library appear only 61% analyzed even though its executable bytes
// had all been scanned; pathological regions still use deterministic sampling.
constexpr size_t kMaxCandidateSites = 65536;
constexpr size_t kMaxDecodedBytes = 16 * 1024 * 1024;
constexpr size_t kMaxDecodeSpanBytes = 1024 * 1024;

double clamp01(double value) {
    return std::max(0.0, std::min(1.0, value));
}

bool starts_with(const std::string& value, const char* prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool is_load(const DisasmInsn& ins) {
    return starts_with(ins.mnemonic, "ldr") || ins.mnemonic == "ldp" ||
           ins.mnemonic == "ldur" || starts_with(ins.mnemonic, "ld1");
}

bool is_pointer_load(const DisasmInsn& ins) {
    if (ins.mnemonic != "ldr" && ins.mnemonic != "ldur") return false;
    // A 32-bit load cannot directly materialize an AArch64 handler pointer.
    // Treat it as a possible opcode fetch instead.
    return ins.operand_count == 0 || ins.operands[0].reg_width_bits != 32;
}

bool is_opcode_load(const DisasmInsn& ins) {
    if (ins.mnemonic == "ldrb" || ins.mnemonic == "ldrh" ||
        ins.mnemonic == "ldrsb" || ins.mnemonic == "ldrsh" ||
        ins.mnemonic == "ldurb" || ins.mnemonic == "ldurh") {
        return true;
    }
    if ((ins.mnemonic == "ldr" || ins.mnemonic == "ldur") &&
        ins.operand_count > 0 && ins.operands[0].reg_width_bits == 32) {
        return true;
    }
    // LDRSW consumes a 32-bit table/value even though the destination is Xn.
    return ins.mnemonic == "ldrsw";
}

bool is_store(const DisasmInsn& ins) {
    return starts_with(ins.mnemonic, "str") || ins.mnemonic == "stp" ||
           ins.mnemonic == "stur" || starts_with(ins.mnemonic, "st1");
}

bool is_transform(const DisasmInsn& ins) {
    static const std::unordered_set<std::string> names = {
        "add", "adds", "sub", "subs", "adc", "sbc", "mul", "madd", "msub",
        "and", "ands", "orr", "eor", "bic", "orn", "eon", "lsl", "lsr", "asr",
        "ubfx", "sbfx", "bfi", "bfxil", "extr", "uxtb", "uxth", "uxtw", "sxtb",
        "sxth", "sxtw", "mov", "mvn", "csel", "csinc", "csinv", "csneg"
    };
    return names.count(ins.mnemonic) != 0;
}

bool is_compare(const DisasmInsn& ins) {
    return ins.mnemonic == "cmp" || ins.mnemonic == "cmn" ||
           ins.mnemonic == "tst" || ins.mnemonic == "ccmp" ||
           ins.mnemonic == "ccmn" || ins.mnemonic == "subs" ||
           ins.mnemonic == "ands" || ins.mnemonic == "cbz" ||
           ins.mnemonic == "cbnz" || ins.mnemonic == "tbz" ||
           ins.mnemonic == "tbnz";
}

bool is_indirect_branch(const DisasmInsn& ins) {
    const std::string& m = ins.mnemonic;
    return m == "br" || m == "braa" || m == "braaz" ||
           m == "brab" || m == "brabz";
}

bool is_indirect_call(const DisasmInsn& ins) {
    const std::string& m = ins.mnemonic;
    return m == "blr" || m == "blraa" || m == "blraaz" ||
           m == "blrab" || m == "blrabz";
}

std::string reg_operand(const DisasmInsn& ins, size_t index) {
    if (index >= ins.operand_count) return "";
    const auto& op = ins.operands[index];
    return op.type == DisasmOperandType::Reg ? op.reg : "";
}

const DisasmOperand* mem_operand(const DisasmInsn& ins) {
    for (size_t i = 0; i < ins.operand_count; ++i) {
        if (ins.operands[i].type == DisasmOperandType::Mem) return &ins.operands[i];
    }
    return nullptr;
}

bool is_non_default_return_dispatch(const DisasmInsn& ins) {
    if (ins.mnemonic != "ret") return false;
    std::string target = reg_operand(ins, 0);
    return !target.empty() && target != "x30" && target != "lr";
}

bool is_indirect_transfer(const DisasmInsn& ins) {
    return is_indirect_branch(ins) || is_indirect_call(ins) ||
           is_non_default_return_dispatch(ins);
}

std::string destination_reg(const DisasmInsn& ins) {
    if (ins.operand_count == 0 || ins.operands[0].type != DisasmOperandType::Reg) return "";
    if (is_store(ins) || is_compare(ins) || ins.is_jump || ins.is_call || ins.is_ret) return "";
    return ins.operands[0].reg;
}

bool uses_reg_as_source(const DisasmInsn& ins, const std::string& reg) {
    if (reg.empty()) return false;
    for (size_t i = 1; i < ins.operand_count; ++i) {
        const auto& op = ins.operands[i];
        if (op.type == DisasmOperandType::Reg && op.reg == reg) return true;
        if (op.type == DisasmOperandType::Mem &&
            (op.mem_base == reg || op.mem_index == reg)) return true;
    }
    return false;
}

bool advances_reg(const DisasmInsn& ins, const std::string& reg) {
    if (reg.empty()) return false;
    if (!(ins.mnemonic == "add" || ins.mnemonic == "sub" ||
          ins.mnemonic == "adds" || ins.mnemonic == "subs")) return false;
    return destination_reg(ins) == reg && uses_reg_as_source(ins, reg);
}

bool address_is_excluded(uint64_t address, const VmpAnalysisContext& context) {
    for (const auto& range : context.excluded_thunk_ranges) {
        if (address >= range.begin && address < range.end) return true;
    }
    return false;
}

bool get_direct_target(const DisasmInsn& ins, uint64_t& target) {
    for (size_t i = 0; i < ins.operand_count; ++i) {
        if (ins.operands[i].type == DisasmOperandType::Imm) {
            target = static_cast<uint64_t>(ins.operands[i].imm);
            return true;
        }
    }
    return false;
}

bool is_backward_direct_branch(const DisasmInsn& ins) {
    if (!ins.is_jump || ins.is_call || is_indirect_transfer(ins)) return false;
    uint64_t target = 0;
    if (!get_direct_target(ins, target) || target >= ins.address) return false;
    return ins.address - target <= 4096;
}

bool is_unconditional_direct_branch(const DisasmInsn& ins) {
    return ins.mnemonic == "b" && ins.is_jump && !ins.is_call &&
           !ins.is_conditional;
}

struct InternalCandidate {
    VmpCandidateEvidence evidence;
    bool strong = false;
    bool medium = false;
    bool conditional = false;
    bool trampoline = false;
    bool call = false;
    bool ret = false;
    bool table_linked = false;
    bool vip_advanced = false;
    bool direct_handler_fetch = false;
    bool back_edge = false;
    bool shared_context = false;
    std::string table_base_reg;
};

struct Accumulator {
    std::vector<InternalCandidate> candidates;
    std::unordered_set<std::string> seen_addresses;
    size_t switch_like_sites = 0;
    size_t vtable_sites = 0;
    size_t excluded_thunk_sites = 0;
    VmpMetrics metrics;
};

size_t previous_block_boundary(const std::vector<DisasmInsn>& insns, size_t branch_index) {
    size_t begin = branch_index > kLookbackInstructions
                     ? branch_index - kLookbackInstructions
                     : 0;
    for (size_t i = branch_index; i > begin; --i) {
        const auto& prev = insns[i - 1];
        const auto& current = insns[i];
        // Resilient disassembly omits invalid data words.  Never let taint jump
        // across that address gap, an unconditional control-flow exit, or a
        // previous terminal transfer into an unrelated basic block.
        if (prev.address + prev.size != current.address ||
            is_unconditional_direct_branch(prev) ||
            is_indirect_transfer(prev) || prev.is_ret) {
            return i;
        }
    }
    return begin;
}

bool stream_has_incoming_dispatch_edge(const std::vector<DisasmInsn>& insns,
                                       size_t begin,
                                       size_t branch_index) {
    if (begin >= insns.size() || branch_index >= insns.size() || begin > branch_index) {
        return false;
    }
    const uint64_t block_begin = insns[begin].address;
    const uint64_t block_end = insns[branch_index].address;
    for (size_t i = 0; i < insns.size(); ++i) {
        if (i >= begin && i <= branch_index) continue;
        const auto& edge = insns[i];
        if (!edge.is_jump || edge.is_call || is_indirect_transfer(edge)) continue;
        uint64_t target = 0;
        if (get_direct_target(edge, target) && target >= block_begin && target <= block_end) {
            return true;
        }
    }
    return false;
}

bool has_vip_advance(const std::vector<DisasmInsn>& insns,
                     size_t fetch_index,
                     size_t branch_index,
                     const std::string& vip) {
    if (fetch_index >= insns.size() || branch_index > insns.size()) return false;
    bool provenance_alive = true;
    bool advanced = insns[fetch_index].writeback;
    for (size_t i = fetch_index + 1; i < branch_index; ++i) {
        if (destination_reg(insns[i]) != vip) continue;
        const bool derives_from_vip = provenance_alive &&
                                      is_transform(insns[i]) &&
                                      uses_reg_as_source(insns[i], vip);
        if (!derives_from_vip) {
            provenance_alive = false;
            advanced = false;
            continue;
        }
        if (advances_reg(insns[i], vip)) advanced = true;
    }
    return provenance_alive && advanced;
}

bool uses_tainted_source(const DisasmInsn& ins,
                         const std::unordered_set<std::string>& tainted) {
    for (size_t i = 1; i < ins.operand_count; ++i) {
        const auto& op = ins.operands[i];
        if (op.type == DisasmOperandType::Reg && tainted.count(op.reg)) return true;
        if (op.type == DisasmOperandType::Mem &&
            (tainted.count(op.mem_base) || tainted.count(op.mem_index))) return true;
    }
    return false;
}

bool opcode_reaches_target(const std::vector<DisasmInsn>& insns,
                           size_t fetch_index,
                           size_t branch_index,
                           const std::string& opcode_reg,
                           const std::string& target_reg) {
    if (opcode_reg.empty() || target_reg.empty() || fetch_index >= branch_index) return false;
    std::unordered_set<std::string> tainted = {opcode_reg};
    for (size_t i = fetch_index + 1; i < branch_index; ++i) {
        const std::string dest = destination_reg(insns[i]);
        if (dest.empty()) continue;
        const bool propagates = uses_tainted_source(insns[i], tainted) &&
                                (is_transform(insns[i]) || is_load(insns[i]));
        tainted.erase(dest);
        if (propagates) tainted.insert(dest);
    }
    return tainted.count(target_reg) != 0;
}

bool window_has_back_edge(const std::vector<DisasmInsn>& insns,
                          size_t begin,
                          size_t end) {
    if (begin >= end || end > insns.size()) return false;
    uint64_t window_begin = insns[begin].address;
    for (size_t i = begin; i < end; ++i) {
        if (!insns[i].is_jump || is_indirect_transfer(insns[i])) continue;
        uint64_t target = 0;
        if (get_direct_target(insns[i], target) &&
            target >= window_begin && target < insns[i].address) {
            return true;
        }
    }
    return false;
}

bool window_has_shared_context(const std::vector<DisasmInsn>& insns,
                               size_t begin,
                               size_t end,
                               const std::string& vip,
                               const std::string& table_base) {
    std::map<std::string, std::set<int32_t>> offsets;
    std::set<std::string> written_bases;
    for (size_t i = begin; i < end && i < insns.size(); ++i) {
        const auto* mem = mem_operand(insns[i]);
        if (!mem || mem->mem_base.empty()) continue;
        const std::string& base = mem->mem_base;
        if (base == "sp" || base == "x29" || base == "fp" ||
            base == vip || base == table_base) continue;
        offsets[base].insert(mem->mem_disp);
        if (is_store(insns[i])) written_bases.insert(base);
    }
    for (const auto& item : offsets) {
        if (item.second.size() >= 2 && written_bases.count(item.first)) return true;
    }
    return false;
}

void append_candidate(Accumulator& acc, InternalCandidate candidate) {
    std::ostringstream key;
    key << candidate.evidence.region << '@' << std::hex << candidate.evidence.address;
    if (!acc.seen_addresses.insert(key.str()).second) return;
    acc.candidates.push_back(std::move(candidate));
}

void collect_from_stream(const std::vector<DisasmInsn>& insns,
                         const VmpAnalysisContext& context,
                         const std::string& region_name,
                         Accumulator& acc) {
    for (size_t branch_index = 0; branch_index < insns.size(); ++branch_index) {
        const DisasmInsn& branch = insns[branch_index];
        const bool indirect = is_indirect_transfer(branch);
        const bool conditional_loop = is_backward_direct_branch(branch);
        if (!indirect && !conditional_loop) continue;
        if (address_is_excluded(branch.address, context)) {
            acc.excluded_thunk_sites++;
            continue;
        }

        const size_t begin = previous_block_boundary(insns, branch_index);
        size_t fetch_index = insns.size();
        std::string opcode_reg;
        std::string vip_reg;
        const DisasmOperand* fetch_mem = nullptr;
        const std::string transfer_target = indirect ? reg_operand(branch, 0) : "";
        size_t fallback_fetch_index = insns.size();
        std::string fallback_opcode_reg;
        std::string fallback_vip_reg;
        const DisasmOperand* fallback_fetch_mem = nullptr;

        for (size_t i = branch_index; i > begin; --i) {
            const DisasmInsn& candidate = insns[i - 1];
            if (!is_opcode_load(candidate)) continue;
            const auto* mem = mem_operand(candidate);
            std::string dest = reg_operand(candidate, 0);
            if (!mem || dest.empty() || mem->mem_base.empty() ||
                mem->mem_base == "sp" || mem->mem_base == "x29" ||
                mem->mem_base == "fp") continue;
            // `ldrb w8, [x8]` destroys x8, so x8 cannot simultaneously remain
            // the VPC. Treating W/X aliases as both opcode and VPC was a major
            // source of false positives in libc++ and codec loops.
            if (dest == mem->mem_base) continue;
            // Do not let a nearer flag/context byte load shadow the real
            // opcode fetch. Only retain loads whose own base preserves
            // provenance and advances before this dispatch site.
            if (!has_vip_advance(insns, i - 1, branch_index, mem->mem_base)) continue;
            if (fallback_fetch_index == insns.size()) {
                fallback_fetch_index = i - 1;
                fallback_opcode_reg = dest;
                fallback_vip_reg = mem->mem_base;
                fallback_fetch_mem = mem;
            }
            if (!indirect || transfer_target.empty() ||
                opcode_reaches_target(insns, i - 1, branch_index, dest, transfer_target)) {
                fetch_index = i - 1;
                opcode_reg = dest;
                vip_reg = mem->mem_base;
                fetch_mem = mem;
                break;
            }
        }
        if (fetch_index == insns.size() && fallback_fetch_index != insns.size()) {
            fetch_index = fallback_fetch_index;
            opcode_reg = fallback_opcode_reg;
            vip_reg = fallback_vip_reg;
            fetch_mem = fallback_fetch_mem;
        }

        if (conditional_loop) {
            if (fetch_index == insns.size()) continue;
            const bool advanced = has_vip_advance(insns, fetch_index, branch_index, vip_reg);
            size_t compare_count = 0;
            size_t condition_count = 0;
            for (size_t i = fetch_index + 1; i <= branch_index; ++i) {
                if (is_compare(insns[i])) compare_count++;
                if (insns[i].is_conditional || starts_with(insns[i].mnemonic, "b.")) condition_count++;
            }
            if (!advanced || compare_count < 2 || condition_count < 2) continue;

            InternalCandidate candidate;
            candidate.conditional = true;
            candidate.medium = true;
            candidate.vip_advanced = true;
            candidate.back_edge = true;
            candidate.shared_context = window_has_shared_context(insns, begin, branch_index,
                                                                  vip_reg, "");
            candidate.evidence.address = branch.address;
            candidate.evidence.region = region_name;
            candidate.evidence.kind = "CONDITIONAL_DISPATCH";
            candidate.evidence.strength = "MEDIUM";
            candidate.evidence.vip_reg = vip_reg;
            candidate.evidence.opcode_reg = opcode_reg;
            candidate.evidence.traits = {"VPC_FETCH", "VPC_ADVANCE", "COMPARE_CHAIN", "BACK_EDGE"};
            if (candidate.shared_context) candidate.evidence.traits.push_back("SHARED_VM_CONTEXT");
            append_candidate(acc, std::move(candidate));
            continue;
        }

        std::string target_reg = transfer_target;
        if (target_reg.empty()) continue;

        size_t direct_fetch_index = insns.size();
        const DisasmOperand* direct_fetch_mem = nullptr;
        for (size_t i = branch_index; i > begin; --i) {
            const DisasmInsn& candidate = insns[i - 1];
            if (!is_pointer_load(candidate) ||
                reg_operand(candidate, 0) != target_reg) continue;
            const auto* mem = mem_operand(candidate);
            if (!mem || mem->mem_base.empty() || mem->mem_base == "sp") continue;
            if (reg_operand(candidate, 0) == mem->mem_base) continue;
            direct_fetch_index = i - 1;
            direct_fetch_mem = mem;
            break;
        }

        bool direct_handler_fetch = false;
        bool direct_fetch_advanced = false;
        if (direct_fetch_index != insns.size() && direct_fetch_mem) {
            direct_fetch_advanced = has_vip_advance(insns, direct_fetch_index,
                                                    branch_index, direct_fetch_mem->mem_base);
            direct_handler_fetch = direct_fetch_advanced;
        }

        if (direct_handler_fetch) {
            fetch_index = direct_fetch_index;
            vip_reg = direct_fetch_mem->mem_base;
            opcode_reg = target_reg;
            fetch_mem = direct_fetch_mem;
        }

        bool advanced = fetch_index != insns.size() &&
                        has_vip_advance(insns, fetch_index, branch_index, vip_reg);
        std::unordered_set<std::string> tainted;
        if (!opcode_reg.empty()) tainted.insert(opcode_reg);
        struct TaintSourceRef {
            uint8_t operand = 0xff;
            bool mem_index = false;
        };
        const size_t taint_window_size = fetch_index < branch_index
                                           ? branch_index - fetch_index
                                           : 0;
        std::vector<TaintSourceRef> tainted_sources(taint_window_size);
        size_t decode_ops = 0;
        if (fetch_index != insns.size()) {
            for (size_t i = fetch_index + 1; i < branch_index; ++i) {
                const std::string dest = destination_reg(insns[i]);
                TaintSourceRef source;
                for (size_t op_index = 1; op_index < insns[i].operand_count; ++op_index) {
                    const auto& op = insns[i].operands[op_index];
                    if (op.type == DisasmOperandType::Reg && tainted.count(op.reg)) {
                        source.operand = static_cast<uint8_t>(op_index);
                        break;
                    }
                    if (op.type == DisasmOperandType::Mem) {
                        if (!op.mem_index.empty() && tainted.count(op.mem_index)) {
                            source.operand = static_cast<uint8_t>(op_index);
                            source.mem_index = true;
                            break;
                        }
                        if (!op.mem_base.empty() && tainted.count(op.mem_base)) {
                            source.operand = static_cast<uint8_t>(op_index);
                            break;
                        }
                    }
                }
                tainted_sources[i - fetch_index] = source;

                if (!dest.empty()) {
                    const bool source_tainted = source.operand != 0xff;
                    const bool propagates = source_tainted &&
                                            (is_transform(insns[i]) || is_load(insns[i]));
                    // A real register definition kills earlier opcode
                    // provenance unless this instruction itself propagates it.
                    tainted.erase(dest);
                    if (propagates) tainted.insert(dest);
                    if (source_tainted && is_transform(insns[i])) decode_ops++;
                }
            }
        }

        bool target_loaded = false;
        bool target_computed = false;
        bool table_linked = tainted.count(target_reg) != 0;
        std::string table_base;
        std::string current_target = target_reg;
        // The candidate window is already strictly bounded.  Trace through the
        // whole basic block so pointer decryptions longer than 16 instructions
        // do not lose the original handler-table load.
        const size_t trace_floor = begin;
        for (size_t i = branch_index; i > trace_floor; --i) {
            const DisasmInsn& def = insns[i - 1];
            if (destination_reg(def) != current_target) continue;
            if (is_load(def)) {
                target_loaded = true;
                const auto* mem = mem_operand(def);
                if (mem) {
                    table_base = mem->mem_base;
                }
                break;
            }
            if (is_transform(def)) {
                target_computed = true;
                const size_t def_index = i - 1;
                const size_t relative_index = def_index >= fetch_index
                                                ? def_index - fetch_index
                                                : tainted_sources.size();
                const TaintSourceRef source_ref = relative_index < tainted_sources.size()
                                                    ? tainted_sources[relative_index]
                                                    : TaintSourceRef{};
                if (source_ref.operand != 0xff &&
                    source_ref.operand < def.operand_count) {
                    const auto& source_op = def.operands[source_ref.operand];
                    std::string source;
                    if (source_op.type == DisasmOperandType::Reg) {
                        source = source_op.reg;
                    } else if (source_op.type == DisasmOperandType::Mem) {
                        source = source_ref.mem_index ? source_op.mem_index
                                                     : source_op.mem_base;
                    }
                    if (!source.empty()) {
                        current_target = source;
                        continue;
                    }
                }
            }
            break;
        }

        if (direct_handler_fetch) {
            target_loaded = true;
            table_linked = false;
            table_base = direct_fetch_mem ? direct_fetch_mem->mem_base : "";
        }

        bool has_adr_base = false;
        for (size_t i = branch_index; i > begin && i + 6 > branch_index; --i) {
            const std::string& m = insns[i - 1].mnemonic;
            if (m == "adr" || m == "adrp") {
                has_adr_base = true;
                break;
            }
        }

        const bool switch_like = fetch_index != insns.size() && !advanced &&
                                 table_linked && is_indirect_branch(branch);
        if (switch_like) {
            acc.switch_like_sites++;
            continue;
        }

        if (is_indirect_call(branch) && target_loaded &&
            fetch_index == insns.size() && !advanced) {
            acc.vtable_sites++;
            continue;
        }

        const bool local_back_edge = window_has_back_edge(insns, begin, branch_index);
        const bool incoming_dispatch_edge = stream_has_incoming_dispatch_edge(
            insns, begin, branch_index);
        const bool local_shared_context = window_has_shared_context(insns, begin, branch_index,
                                                                    vip_reg, table_base);
        const bool direct_call = direct_handler_fetch && is_indirect_call(branch);
        const bool classic_strong = fetch_index != insns.size() && advanced &&
                                    target_loaded && table_linked;
        const bool classic_medium = fetch_index != insns.size() && advanced &&
                                    (target_loaded || target_computed) &&
                                    (table_linked || decode_ops >= 1);
        // Advancing through an array of function pointers and calling each item
        // is a common callback/destructor pattern in C++ libraries. A BLR-based
        // direct fetch therefore remains supporting/medium evidence even when
        // it sits in a stateful loop. A call-threaded VM can still become
        // strong through closed opcode-to-handler table dataflow. BR/RET direct
        // threading remains strong because control does not return like a
        // conventional callback.
        const bool direct_strong = direct_handler_fetch && advanced &&
                                   !direct_call;
        const bool direct_medium = direct_handler_fetch && advanced &&
                                   direct_call;
        const bool trampoline = fetch_index == insns.size() &&
                                is_indirect_branch(branch) && has_adr_base &&
                                (target_loaded || target_computed);

        if (!classic_strong && !classic_medium && !direct_strong &&
            !direct_medium && !trampoline) continue;

        InternalCandidate candidate;
        candidate.strong = classic_strong || direct_strong;
        candidate.medium = !candidate.strong && (classic_medium || direct_medium);
        candidate.trampoline = trampoline && !candidate.strong && !candidate.medium;
        candidate.call = is_indirect_call(branch);
        candidate.ret = is_non_default_return_dispatch(branch);
        candidate.table_linked = table_linked;
        candidate.vip_advanced = advanced;
        candidate.direct_handler_fetch = direct_handler_fetch;
        candidate.back_edge = local_back_edge || incoming_dispatch_edge;
        candidate.shared_context = local_shared_context;
        candidate.table_base_reg = table_base;

        const bool abi_ip_thunk = candidate.direct_handler_fetch &&
                                  (vip_reg == "x16" || vip_reg == "x17") &&
                                  (target_reg == "x16" || target_reg == "x17") &&
                                  !candidate.back_edge && !candidate.shared_context;
        if (abi_ip_thunk) {
            candidate.strong = false;
            candidate.medium = false;
            candidate.trampoline = true;
        }

        candidate.evidence.address = branch.address;
        candidate.evidence.region = region_name;
        candidate.evidence.vip_reg = vip_reg;
        candidate.evidence.opcode_reg = opcode_reg;
        candidate.evidence.target_reg = target_reg;
        candidate.evidence.strength = candidate.strong ? "STRONG" :
                                              (candidate.medium ? "MEDIUM" : "SUPPORTING");
        if (abi_ip_thunk) candidate.evidence.kind = "ABI_IP_TRAMPOLINE";
        else if (candidate.ret) candidate.evidence.kind = "RETURN_THREADED";
        else if (candidate.call) candidate.evidence.kind = "CALL_THREADED";
        else if (candidate.direct_handler_fetch) candidate.evidence.kind = "DIRECT_THREADED";
        else if (candidate.trampoline) candidate.evidence.kind = "THREADED_TRAMPOLINE";
        else candidate.evidence.kind = "REGISTER_DISPATCH";

        if (fetch_mem) candidate.evidence.traits.push_back("VPC_FETCH");
        if (advanced) candidate.evidence.traits.push_back("VPC_ADVANCE");
        if (table_linked) candidate.evidence.traits.push_back("OPCODE_TO_TARGET_DATAFLOW");
        if (direct_handler_fetch) candidate.evidence.traits.push_back("HANDLER_POINTER_FETCH");
        if (target_loaded) candidate.evidence.traits.push_back("TARGET_TABLE_LOAD");
        if (candidate.back_edge) candidate.evidence.traits.push_back("BACK_EDGE");
        if (incoming_dispatch_edge) {
            candidate.evidence.traits.push_back("HANDLER_RETURN_EDGE");
        }
        if (candidate.shared_context) candidate.evidence.traits.push_back("SHARED_VM_CONTEXT");
        append_candidate(acc, std::move(candidate));
    }
}

size_t cluster_size(const std::vector<InternalCandidate>& candidates) {
    std::map<std::string, std::vector<uint64_t>> by_region;
    for (const auto& candidate : candidates) {
        by_region[candidate.evidence.region].push_back(candidate.evidence.address);
    }
    size_t best = 0;
    for (auto& item : by_region) {
        auto& addresses = item.second;
        std::sort(addresses.begin(), addresses.end());
        size_t left = 0;
        for (size_t right = 0; right < addresses.size(); ++right) {
            while (addresses[right] - addresses[left] > 4096) left++;
            best = std::max(best, right - left + 1);
        }
    }
    return best;
}

size_t max_local_vip_sites(const std::vector<InternalCandidate>& candidates,
                           bool strong_only,
                           uint64_t span) {
    std::map<std::string, std::vector<uint64_t>> groups;
    for (const auto& candidate : candidates) {
        if (candidate.conditional || candidate.trampoline) continue;
        if (!(candidate.strong || candidate.medium)) continue;
        if (strong_only && !candidate.strong) continue;
        if (candidate.evidence.vip_reg.empty()) continue;
        std::string key = candidate.evidence.region + "|" + candidate.evidence.vip_reg;
        groups[key].push_back(candidate.evidence.address);
    }

    size_t best = 0;
    for (auto& item : groups) {
        auto& addresses = item.second;
        std::sort(addresses.begin(), addresses.end());
        size_t left = 0;
        for (size_t right = 0; right < addresses.size(); ++right) {
            while (addresses[right] - addresses[left] > span) left++;
            best = std::max(best, right - left + 1);
        }
    }
    return best;
}

size_t max_local_strong_family(const std::vector<InternalCandidate>& candidates,
                               uint64_t span) {
    std::map<std::string, std::vector<uint64_t>> groups;
    for (const auto& candidate : candidates) {
        if (!candidate.strong || candidate.conditional || candidate.trampoline) continue;
        if (candidate.evidence.vip_reg.empty()) continue;
        const std::string key = candidate.evidence.region + "|" +
                                candidate.evidence.vip_reg + "|" +
                                candidate.table_base_reg;
        groups[key].push_back(candidate.evidence.address);
    }

    size_t best = 0;
    for (auto& item : groups) {
        auto& addresses = item.second;
        std::sort(addresses.begin(), addresses.end());
        size_t left = 0;
        for (size_t right = 0; right < addresses.size(); ++right) {
            while (addresses[right] - addresses[left] > span) left++;
            best = std::max(best, right - left + 1);
        }
    }
    return best;
}

double tier(size_t value,
            size_t t1, double v1,
            size_t t2, double v2,
            size_t t3, double v3,
            size_t t4, double v4) {
    if (value >= t4) return v4;
    if (value >= t3) return v3;
    if (value >= t2) return v2;
    if (value >= t1) return v1;
    return 0.0;
}

VmpDeepResult finalize_result(Accumulator& acc,
                              const VmpAnalysisContext& context,
                              bool scan_truncated,
                              double coverage) {
    VmpDeepResult result;
    result.analyzed = true;
    result.scan_truncated = scan_truncated;
    result.coverage = clamp01(coverage);
    result.metrics = acc.metrics;
    // Observable describes the bytes we really inspected.  Packing is a
    // separate limitation: the visible stub may be analyzable even though the
    // protected payload is not.
    result.observable = result.metrics.scanned_bytes > 0;

    size_t strong = 0;
    size_t medium = 0;
    size_t eligible = 0;
    size_t classic_medium = 0;
    size_t classic_eligible = 0;
    size_t table_linked = 0;
    size_t advanced = 0;
    size_t direct_handler = 0;
    size_t direct_call_handler = 0;
    size_t back_edges = 0;
    size_t shared_context = 0;
    size_t trampoline = 0;
    size_t call = 0;
    size_t ret = 0;
    size_t conditional = 0;
    size_t classic_back_edges = 0;
    size_t classic_shared_context = 0;
    bool has_dispatcher_cycle = false;
    bool has_closed_central_dispatcher = false;

    for (const auto& candidate : acc.candidates) {
        if (candidate.strong) strong++;
        if (candidate.medium) medium++;
        if (candidate.strong || candidate.medium || candidate.conditional) eligible++;
        if (!candidate.conditional && !candidate.trampoline &&
            (candidate.strong || candidate.medium)) {
            classic_eligible++;
            if (candidate.medium) classic_medium++;
            if (candidate.back_edge) classic_back_edges++;
            if (candidate.shared_context) classic_shared_context++;
        }
        if (candidate.table_linked) table_linked++;
        if (candidate.vip_advanced) advanced++;
        if (candidate.direct_handler_fetch && !candidate.trampoline) direct_handler++;
        if (candidate.direct_handler_fetch && candidate.call && !candidate.trampoline) {
            direct_call_handler++;
        }
        if (candidate.back_edge) back_edges++;
        if (candidate.shared_context) shared_context++;
        if (candidate.trampoline) trampoline++;
        if (candidate.call) call++;
        if (candidate.ret) ret++;
        if (candidate.conditional) conditional++;
        if (candidate.strong && candidate.table_linked &&
            candidate.back_edge) {
            has_dispatcher_cycle = true;
            if (candidate.shared_context) has_closed_central_dispatcher = true;
        }
    }

    const size_t dominant_vip = max_local_vip_sites(acc.candidates, false, 64 * 1024);
    const size_t dominant_strong_vip = max_local_vip_sites(acc.candidates, true, 64 * 1024);
    const size_t dominant_strong_family = max_local_strong_family(acc.candidates, 16 * 1024);
    size_t max_cluster = cluster_size(acc.candidates);

    result.metrics.unique_candidates = acc.candidates.size();
    result.metrics.excluded_thunk_sites = acc.excluded_thunk_sites;
    result.metrics.strong_candidates = strong;
    result.metrics.medium_candidates = medium;
    result.metrics.call_dispatch_candidates = call;
    result.metrics.conditional_dispatch_candidates = conditional;
    result.metrics.table_linked_candidates = table_linked;
    result.metrics.vip_advanced_candidates = advanced;
    result.metrics.trampoline_candidates = trampoline;
    result.metrics.dominant_vip_sites = dominant_vip;
    result.metrics.max_cluster_sites = max_cluster;
    result.metrics.direct_dispatch_candidates = eligible >= call + ret
                                                ? eligible - call - ret
                                                : 0;

    double dataflow_family = tier(strong, 1, 0.13, 2, 0.25, 3, 0.34, 4, 0.44);
    dataflow_family += tier(classic_medium, 2, 0.04, 3, 0.07, 5, 0.10, 8, 0.12);
    if (table_linked >= 2 || direct_handler >= 2) dataflow_family += 0.08;
    dataflow_family = std::min(0.52, dataflow_family);

    double ecology_family = tier(classic_eligible, 2, 0.04, 3, 0.08, 4, 0.11, 6, 0.14);
    ecology_family += tier(dominant_vip, 2, 0.03, 3, 0.06, 4, 0.08, 6, 0.09);
    ecology_family += tier(max_cluster, 3, 0.03, 4, 0.05, 6, 0.06, 10, 0.07);
    ecology_family = std::min(0.25, ecology_family);

    double state_family = tier(classic_shared_context, 1, 0.04, 2, 0.06, 3, 0.08, 5, 0.10);
    state_family += tier(classic_back_edges, 1, 0.03, 2, 0.05, 3, 0.07, 5, 0.08);
    if (classic_eligible >= 4) state_family += 0.04;
    if ((call > 0 || ret > 0) && classic_eligible >= 3) state_family += 0.03;
    state_family = std::min(0.20, state_family);

    double classic_structure = clamp01(dataflow_family + ecology_family + state_family);
    const bool single_closed_dataflow = strong >= 1 && table_linked >= 1 && advanced >= 1;
    if (single_closed_dataflow) {
        // One static central dispatcher is common.  A closed VPC -> opcode ->
        // handler path is enough for a medium, reviewable verdict, but not a
        // high-confidence VMP label without topology or protection intent.
        classic_structure = std::max(classic_structure, 0.56);
    }
    if (has_dispatcher_cycle) classic_structure = std::max(classic_structure, 0.70);
    const bool closed_central_dispatcher = has_closed_central_dispatcher;
    if (closed_central_dispatcher) {
        // A VM commonly has one static central dispatcher executed repeatedly.
        // Do not force several unrelated static sites when one site already
        // closes opcode dataflow, state mutation and a dispatcher loop.
        classic_structure = std::max(classic_structure, 0.78);
    }
    double trampoline_structure = tier(trampoline, 4, 0.20, 8, 0.34, 12, 0.43, 20, 0.50);
    if (trampoline >= 4 && max_cluster >= 4) trampoline_structure += 0.10;
    trampoline_structure = std::min(0.62, trampoline_structure);
    double conditional_structure = tier(conditional, 1, 0.18, 2, 0.28, 3, 0.36, 5, 0.42);
    if (conditional >= 2 && dominant_vip >= 2) conditional_structure += 0.08;

    result.structure_score = clamp01(std::max({classic_structure,
                                                trampoline_structure,
                                                conditional_structure}));

    const bool confirmed_runtime = context.known_runtime ||
                                   context.runtime_evidence_classes >= 2;
    const bool weak_runtime = !confirmed_runtime &&
                              context.runtime_evidence_classes == 1;
    const bool decisive_closed = closed_central_dispatcher ||
        (strong >= 4 && table_linked >= 3 && dominant_strong_family >= 3 &&
         classic_shared_context >= 2 && classic_back_edges >= 2);

    double intent = 0.0;
    if (context.vmp_metadata_marker) intent += 0.45;
    if (context.custom_linker_marker) intent += 0.25;
    if (context.custom_linker_likely) intent += 0.15;
    if (context.has_large_entropy_blob) intent += 0.06;
    if (context.has_init_array && context.import_count <= 8) intent += 0.04;
    if (!confirmed_runtime && result.structure_score >= 0.70) intent += 0.10;
    result.protection_intent_score = clamp01(intent);

    const bool protected_runtime_coexistence = confirmed_runtime && decisive_closed &&
        (context.vmp_metadata_marker ||
         (context.custom_linker_marker &&
          result.protection_intent_score >= 0.45));

    double alternatives = 0.0;
    if (confirmed_runtime && result.structure_score >= 0.25) {
        alternatives += protected_runtime_coexistence ? 0.10 : 0.30;
    } else if (weak_runtime && result.structure_score >= 0.25) {
        alternatives += 0.08;
    }
    if (table_linked == 0 && direct_call_handler >= 4) {
        alternatives += context.vmp_metadata_marker ? 0.04 : 0.12;
    }
    if (eligible == 0) {
        if (acc.switch_like_sites >= 3) alternatives += 0.15;
        else if (acc.switch_like_sites > 0) alternatives += 0.06;
        if (acc.vtable_sites >= 4) alternatives += 0.10;
        else if (acc.vtable_sites > 0) alternatives += 0.04;
    } else if (eligible < 3 && strong < 3 &&
               (acc.switch_like_sites > 0 || acc.vtable_sites > 0)) {
        alternatives += 0.04;
    }
    if (eligible == 1 && !context.vmp_metadata_marker) alternatives += 0.08;
    if (context.control_flow_obfuscation_likely && strong <= 1 &&
        !context.vmp_metadata_marker && !context.custom_linker_marker) {
        alternatives += 0.22;
    }
    result.alternative_penalty = std::min(0.45, alternatives);
    result.score = clamp01(result.structure_score * 0.82 +
                           result.protection_intent_score * 0.18 -
                           result.alternative_penalty);

    const bool classic_gate =
        ((strong >= 4 && dominant_strong_family >= 3 &&
          table_linked >= 3 &&
          (classic_shared_context >= 1 || classic_back_edges >= 1)) ||
         (strong >= 3 && dominant_strong_family >= 3 &&
          (classic_shared_context >= 1 || classic_back_edges >= 1) &&
          table_linked >= 2));
    const bool direct_threaded_gate = strong >= 4 && dominant_strong_family >= 3 &&
                                      direct_handler >= 3 &&
                                      result.protection_intent_score >= 0.35;
    const bool trampoline_gate = trampoline >= 8 && max_cluster >= 6 &&
                                 result.protection_intent_score >= 0.35;
    const bool conditional_gate = conditional >= 2 && dominant_vip >= 2 &&
                                  result.protection_intent_score >= 0.45;
    const bool metadata_gate = context.vmp_metadata_marker && strong >= 2 &&
                               dominant_strong_family >= 2;
    const bool metadata_threaded_gate = context.vmp_metadata_marker &&
                                        direct_handler >= 8 && dominant_vip >= 4 &&
                                        (classic_shared_context >= 3 ||
                                         classic_back_edges >= 3);
    const bool intent_gate = result.protection_intent_score >= 0.45 &&
                             strong >= 3 && dominant_strong_vip >= 2;
    const bool central_dispatcher_gate = has_dispatcher_cycle &&
                                         result.protection_intent_score >= 0.45;
    const bool runtime_override = !confirmed_runtime ||
                                  protected_runtime_coexistence ||
                                  result.protection_intent_score >= 0.55;
    const bool weak_runtime_override = !weak_runtime ||
                                       (decisive_closed &&
                                        result.protection_intent_score >= 0.15);

    const bool packing_override = !context.code_obscured_by_packing ||
                                  (context.vmp_metadata_marker &&
                                   result.structure_score >= 0.70);
    // High-confidence output needs either explicit protection metadata, a
    // genuinely repeated closed dataflow, or a sparse but centralized
    // high-intent dispatcher.  Generic loader markers plus one to four local
    // C++ switch/callback sites are too common to become VMP providers.
    const bool high_precision_structure =
        context.vmp_metadata_marker || strong >= 5 ||
        (!context.known_non_vm_framework && strong >= 2 && dominant_vip >= 8 &&
         result.protection_intent_score >= 0.45 &&
         (has_dispatcher_cycle || closed_central_dispatcher));
    const double verdict_threshold = metadata_threaded_gate ? 0.56 :
                                     (metadata_gate ? 0.60 : 0.67);
    result.possible = runtime_override && weak_runtime_override && packing_override &&
                       high_precision_structure &&
                       (classic_gate || direct_threaded_gate || trampoline_gate ||
                        conditional_gate || metadata_gate || metadata_threaded_gate ||
                        intent_gate ||
                        central_dispatcher_gate) &&
                      result.score >= verdict_threshold;

    const double top_structure = std::max({classic_structure,
                                           trampoline_structure,
                                           conditional_structure});
    size_t tied_profiles = 0;
    if (classic_structure > 0.0 && top_structure - classic_structure <= 0.08) tied_profiles++;
    if (trampoline_structure > 0.0 && top_structure - trampoline_structure <= 0.08) tied_profiles++;
    if (conditional_structure > 0.0 && top_structure - conditional_structure <= 0.08) tied_profiles++;
    if (tied_profiles > 1) result.profile = "MIXED";
    else if (top_structure == trampoline_structure && trampoline_structure > 0.0) result.profile = "THREADED_TRAMPOLINE";
    else if (top_structure == conditional_structure && conditional_structure > 0.0) result.profile = "CONDITIONAL_DISPATCH";
    else if (call > 0 && call >= result.metrics.direct_dispatch_candidates) result.profile = "CALL_THREADED";
    else if (ret > 0) result.profile = "RETURN_THREADED";
    else if (direct_handler > 0) result.profile = "DIRECT_THREADED";
    else if (eligible > 0) result.profile = "REGISTER_DISPATCH";

    if (context.code_obscured_by_packing && !result.possible) {
        result.outcome = "INCONCLUSIVE_PACKED";
        result.confidence = "UNKNOWN";
        result.limitation = "Executable VM code may be encrypted or released only at runtime";
    } else if (scan_truncated) {
        result.outcome = result.possible ? "LIKELY_VMP" : "PARTIAL_ANALYSIS";
        result.confidence = result.possible ? "HIGH" : "UNKNOWN";
        result.limitation = "Candidate analysis budget was reached";
    } else if (result.possible) {
        result.outcome = "LIKELY_VMP";
        result.confidence = "HIGH";
    } else if (confirmed_runtime && !protected_runtime_coexistence) {
        // Once a legitimate runtime has two independent identity classes, its
        // ordinary VM/switch topology is a decisive alternative explanation.
        // It must never fall through to SUSPICIOUS_VM_STRUCTURE merely because
        // the topology is dense.  Protection-specific coexistence is handled
        // by result.possible above.
        result.outcome = result.structure_score >= 0.25
            ? "VM_LIKE_INTERPRETER"
            : "NO_VMP_EVIDENCE";
        result.confidence = "LOW";
        result.alternative_explanation = context.known_runtime_name;
    } else if (!(context.control_flow_obfuscation_likely && strong <= 1 &&
                  !context.vmp_metadata_marker && !context.custom_linker_marker) &&
               (strong > 0 || context.vmp_metadata_marker ||
                (context.custom_linker_likely &&
                 result.protection_intent_score >= 0.45)) &&
               (result.score >= 0.50 || result.structure_score >= 0.55)) {
        result.outcome = "SUSPICIOUS_VM_STRUCTURE";
        result.confidence = "MEDIUM";
    } else {
        result.outcome = "NO_VMP_EVIDENCE";
        result.confidence = "LOW";
    }
    if (result.alternative_explanation.empty() && table_linked == 0 &&
        direct_call_handler >= 4) {
        result.alternative_explanation = "function-pointer callback/destructor loop";
    } else if (result.alternative_explanation.empty() &&
               context.control_flow_obfuscation_likely && strong <= 1 &&
               !context.vmp_metadata_marker) {
        result.alternative_explanation =
            "control-flow obfuscation or packer state machine";
    } else if (result.alternative_explanation.empty() && weak_runtime &&
               result.structure_score >= 0.25) {
        result.alternative_explanation = context.known_runtime_name;
    }

    if (strong > 0) {
        result.signals.push_back("发现去重后的强分发数据流候选=" + std::to_string(strong));
    }
    if (table_linked > 0) {
        result.signals.push_back("opcode到handler目标存在数据依赖候选=" +
                                 std::to_string(table_linked));
    }
    if (dominant_vip >= 2) {
        result.signals.push_back("多个独立候选共享VPC/VIP寄存器=" +
                                 std::to_string(dominant_vip));
    }
    if (shared_context > 0) {
        result.signals.push_back("候选访问共享VM上下文=" + std::to_string(shared_context));
    }
    if (back_edges > 0) {
        result.signals.push_back("候选控制流存在回边=" + std::to_string(back_edges));
    }
    if (call > 0) {
        result.signals.push_back("识别到call-threaded间接调用候选=" + std::to_string(call));
    }
    if (ret > 0) {
        result.signals.push_back("识别到return-threaded候选=" + std::to_string(ret));
    }
    if (conditional > 0) {
        result.signals.push_back("识别到条件链分发候选=" + std::to_string(conditional));
    }
    if (trampoline > 0) {
        result.signals.push_back("识别到线程化跳板候选=" + std::to_string(trampoline));
    }
    if (acc.switch_like_sites > 0) {
        result.signals.push_back("已隔离普通switch跳表替代解释=" +
                                 std::to_string(acc.switch_like_sites));
    }
    if (acc.vtable_sites > 0) {
        result.signals.push_back("已隔离vtable/函数指针调用替代解释=" +
                                 std::to_string(acc.vtable_sites));
    }
    if (context.known_runtime && result.structure_score >= 0.25) {
        result.signals.push_back("存在合法解释器/运行时替代解释: " +
                                 context.known_runtime_name);
    }
    if (context.vmp_metadata_marker) result.signals.push_back("存在保护型VMP元数据辅助证据");
    if (context.code_obscured_by_packing) result.signals.push_back("打包/加密降低静态可观测性");

    std::vector<InternalCandidate> ranked = acc.candidates;
    std::stable_sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
        auto rank = [](const InternalCandidate& c) {
            if (c.strong) return 3;
            if (c.medium || c.conditional) return 2;
            return 1;
        };
        if (rank(a) != rank(b)) return rank(a) > rank(b);
        return a.evidence.address < b.evidence.address;
    });
    const size_t evidence_limit = std::min<size_t>(ranked.size(), 12);
    result.candidates.reserve(evidence_limit);
    for (size_t i = 0; i < evidence_limit; ++i) {
        result.candidates.push_back(std::move(ranked[i].evidence));
    }
    return result;
}

bool is_indirect_transfer_word(uint32_t word) {
    constexpr uint32_t mask = 0xfffffc1fU;
    const uint32_t opcode = word & mask;
    if (opcode == 0xd61f0000U || // BR
        opcode == 0xd63f0000U) { // BLR
        return true;
    }
    if (opcode == 0xd65f0000U) { // RET xN
        const uint32_t target_reg = (word >> 5) & 0x1fU;
        return target_reg != 30U; // ordinary RET x30 is not a dispatcher
    }

    // ARMv8.3 pointer-authenticated indirect branches/calls. The two-register
    // BRAA/BRAB forms and the *Z forms have different fixed encodings, so keep
    // both masks explicit instead of broad-matching unrelated system opcodes.
    const uint32_t auth_pair = word & 0xfffff800U;
    if (auth_pair == 0xd71f0800U || // BRAA/BRAB
        auth_pair == 0xd73f0800U) { // BLRAA/BLRAB
        return true;
    }
    const uint32_t auth_zero = word & 0xfffff81fU;
    return auth_zero == 0xd61f081fU || // BRAAZ/BRABZ
           auth_zero == 0xd63f081fU;   // BLRAAZ/BLRABZ
}

int64_t sign_extend(uint64_t value, unsigned bits) {
    const uint64_t sign = 1ULL << (bits - 1);
    return static_cast<int64_t>((value ^ sign) - sign);
}

bool is_near_backward_branch_word(uint32_t word) {
    int64_t displacement = 0;
    if ((word & 0xfc000000U) == 0x14000000U) {          // B imm26 (not BL)
        displacement = sign_extend(word & 0x03ffffffU, 26) * 4;
    } else if ((word & 0xff000010U) == 0x54000000U) {   // B.cond imm19
        displacement = sign_extend((word >> 5) & 0x7ffffU, 19) * 4;
    } else if ((word & 0x7e000000U) == 0x34000000U) {   // CBZ/CBNZ
        displacement = sign_extend((word >> 5) & 0x7ffffU, 19) * 4;
    } else if ((word & 0x7e000000U) == 0x36000000U) {   // TBZ/TBNZ
        displacement = sign_extend((word >> 5) & 0x3fffU, 14) * 4;
    }
    return displacement < 0 && displacement >= -4096;
}

struct DecodeSpan {
    size_t begin = 0;
    size_t end = 0;
    size_t site_count = 0;
};

} // namespace

VmpDeepResult analyze_vmp_instruction_stream(const std::vector<DisasmInsn>& instructions,
                                             const VmpAnalysisContext& context,
                                             const std::string& region_name) {
    Accumulator acc;
    acc.metrics.executable_bytes = instructions.size() * 4ULL;
    acc.metrics.scanned_bytes = acc.metrics.executable_bytes;
    acc.metrics.decoded_candidate_bytes = acc.metrics.executable_bytes;
    acc.metrics.instruction_slots = instructions.size();
    for (const auto& instruction : instructions) {
        if (is_indirect_transfer(instruction)) acc.metrics.raw_indirect_transfers++;
    }
    collect_from_stream(instructions, context, region_name, acc);
    return finalize_result(acc, context, false, instructions.empty() ? 0.0 : 1.0);
}

VmpDeepResult analyze_vmp_regions(const std::vector<ExecutableRegionView>& regions,
                                  const VmpAnalysisContext& context) {
    Accumulator acc;
    Arm64DisasmEngine engine;
    if (!engine.init()) {
        VmpDeepResult failed;
        failed.outcome = "ANALYSIS_ERROR";
        failed.confidence = "UNKNOWN";
        failed.limitation = "Capstone initialization failed";
        return failed;
    }

    size_t total_sites = 0;
    size_t processed_sites = 0;
    size_t decoded_budget = 0;
    bool truncated = false;
    size_t remaining_regions = 0;
    for (const auto& region : regions) {
        if (region.data && region.size >= 4) remaining_regions++;
    }

    for (size_t region_index = 0; region_index < regions.size(); ++region_index) {
        const auto& region = regions[region_index];
        if (!region.data || region.size < 4) continue;
        if (region.virtual_address > UINT64_MAX - region.size) {
            truncated = true;
            if (remaining_regions > 0) remaining_regions--;
            continue;
        }
        const size_t remaining_global_budget = decoded_budget < kMaxDecodedBytes
                                                 ? kMaxDecodedBytes - decoded_budget
                                                 : 0;
        // Reserve an equal share for every later RX segment.  Unused capacity
        // automatically rolls forward, so a huge first segment cannot starve a
        // smaller protected segment near the end of the program headers.
        const size_t region_decode_budget = remaining_regions > 0
                                              ? remaining_global_budget / remaining_regions
                                              : remaining_global_budget;
        if (remaining_regions > 0) remaining_regions--;
        acc.metrics.executable_bytes += region.size;
        acc.metrics.scanned_bytes += region.size;
        acc.metrics.instruction_slots += region.size / 4;

        size_t transfer_count = 0;
        size_t loop_count = 0;
        for (size_t offset = 0; offset + 4 <= region.size; offset += 4) {
            uint32_t word = 0;
            std::memcpy(&word, region.data + offset, sizeof(word));
            const bool indirect = is_indirect_transfer_word(word);
            const bool backward = is_near_backward_branch_word(word);
            if (!indirect && !backward) continue;
            if (address_is_excluded(region.virtual_address + offset, context)) {
                acc.excluded_thunk_sites++;
                continue;
            }
            if (indirect) {
                acc.metrics.raw_indirect_transfers++;
                transfer_count++;
            } else {
                loop_count++;
            }
        }

        const size_t region_site_count = transfer_count + loop_count;
        total_sites += region_site_count;
        const size_t transfer_quota = std::min(transfer_count, kMaxCandidateSites);
        const size_t loop_quota = std::min(loop_count,
                                           kMaxCandidateSites - transfer_quota);
        if (region_site_count > kMaxCandidateSites) truncated = true;

        // Second pass performs deterministic, evenly spaced sampling without
        // retaining every attacker-controlled branch offset in memory.
        std::vector<size_t> transfer_sites;
        std::vector<size_t> loop_sites;
        transfer_sites.reserve(transfer_quota);
        loop_sites.reserve(loop_quota);
        size_t transfer_seen = 0;
        size_t loop_seen = 0;
        for (size_t offset = 0; offset + 4 <= region.size; offset += 4) {
            uint32_t word = 0;
            std::memcpy(&word, region.data + offset, sizeof(word));
            const bool indirect = is_indirect_transfer_word(word);
            const bool backward = is_near_backward_branch_word(word);
            if (!indirect && !backward) continue;
            if (address_is_excluded(region.virtual_address + offset, context)) continue;
            if (indirect) {
                const size_t ordinal = transfer_seen++;
                if (transfer_quota > 0 && transfer_sites.size() < transfer_quota &&
                    ordinal == (transfer_sites.size() * transfer_count) / transfer_quota) {
                    transfer_sites.push_back(offset);
                }
            } else {
                const size_t ordinal = loop_seen++;
                if (loop_quota > 0 && loop_sites.size() < loop_quota &&
                    ordinal == (loop_sites.size() * loop_count) / loop_quota) {
                    loop_sites.push_back(offset);
                }
            }
        }

        std::vector<size_t> sites;
        sites.reserve(transfer_sites.size() + loop_sites.size());
        sites.insert(sites.end(), transfer_sites.begin(), transfer_sites.end());
        sites.insert(sites.end(), loop_sites.begin(), loop_sites.end());
        std::sort(sites.begin(), sites.end());
        if (sites.empty()) continue;

        std::vector<DecodeSpan> spans;
        const size_t region_merge_limit = std::max<size_t>(
            4, std::min(kMaxDecodeSpanBytes, region_decode_budget));
        for (size_t site : sites) {
            DecodeSpan span;
            const size_t before = kLookbackInstructions * 4;
            span.begin = site > before ? site - before : 0;
            span.end = std::min(region.size, site + (kLookaheadInstructions + 1) * 4);
            span.begin &= ~size_t(3);
            span.end &= ~size_t(3);
            span.site_count = 1;
            const size_t merged_end = spans.empty() ? span.end
                                                     : std::max(spans.back().end, span.end);
            const bool merge_fits = !spans.empty() &&
                                    merged_end - spans.back().begin <= region_merge_limit;
            if (!spans.empty() && span.begin <= spans.back().end && merge_fits) {
                spans.back().end = merged_end;
                spans.back().site_count++;
            } else {
                spans.push_back(span);
            }
        }

        size_t region_decoded_bytes = 0;
        for (const auto& span : spans) {
            const size_t span_size = span.end > span.begin ? span.end - span.begin : 0;
            if (span_size == 0) continue;
            if (region_decoded_bytes + span_size > region_decode_budget ||
                decoded_budget + span_size > kMaxDecodedBytes) {
                truncated = true;
                continue;
            }
            region_decoded_bytes += span_size;
            decoded_budget += span_size;
            processed_sites += span.site_count;
            acc.metrics.decoded_candidate_bytes += span_size;
            auto instructions = engine.disasm_aligned_resilient(
                region.data + span.begin,
                span_size,
                region.virtual_address + span.begin,
                0);
            std::string region_label = region.name.empty()
                                         ? "RX#" + std::to_string(region_index)
                                         : region.name;
            collect_from_stream(instructions, context, region_label, acc);
        }
    }

    if (acc.metrics.executable_bytes == 0) {
        VmpDeepResult unavailable;
        unavailable.outcome = context.code_obscured_by_packing
                                ? "INCONCLUSIVE_PACKED"
                                : "NO_EXECUTABLE_CODE";
        unavailable.confidence = "UNKNOWN";
        unavailable.limitation = "No observable executable region was available";
        return unavailable;
    }

    double coverage = 0.0;
    if (acc.metrics.executable_bytes > 0) {
        coverage = total_sites == 0 ? 1.0 :
                   static_cast<double>(processed_sites) / static_cast<double>(total_sites);
    }
    return finalize_result(acc, context, truncated, coverage);
}
