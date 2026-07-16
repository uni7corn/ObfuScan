
#include "disasm_arm64.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
#include <string>

struct Arm64DisasmEngine::Impl {
    csh handle = 0;
    bool inited = false;
};

Arm64DisasmEngine::Arm64DisasmEngine() : impl_(new Impl()) {}

Arm64DisasmEngine::~Arm64DisasmEngine() {
    close();
    delete impl_;
    impl_ = nullptr;
}

bool Arm64DisasmEngine::init() {
    if (impl_->inited) return true;

    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &impl_->handle);
    if (err != CS_ERR_OK) {
        return false;
    }

    cs_option(impl_->handle, CS_OPT_DETAIL, CS_OPT_ON);
    impl_->inited = true;
    return true;
}

void Arm64DisasmEngine::close() {
    if (impl_ && impl_->inited) {
        cs_close(&impl_->handle);
        impl_->inited = false;
        impl_->handle = 0;
    }
}

static bool starts_with(const std::string& s, const char* prefix) {
    return s.rfind(prefix, 0) == 0;
}

static std::string canonical_reg_name(csh handle, unsigned int reg_id) {
    if (reg_id == 0) return "";
    const char* raw = cs_reg_name(handle, reg_id);
    if (!raw) return "";

    std::string name(raw);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // VMP data-flow should treat the Wn and Xn views as the same register.
    if (name.size() >= 2 && name[0] == 'w' &&
        std::all_of(name.begin() + 1, name.end(),
                    [](unsigned char c) { return std::isdigit(c) != 0; })) {
        name[0] = 'x';
    } else if (name == "wsp") {
        name = "sp";
    }
    return name;
}

static uint8_t register_width_bits(csh handle, unsigned int reg_id) {
    if (reg_id == 0) return 0;
    const char* raw = cs_reg_name(handle, reg_id);
    if (!raw) return 0;
    std::string name(raw);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (name == "wsp" || (!name.empty() && name[0] == 'w')) return 32;
    if (name == "sp" || (!name.empty() && name[0] == 'x') ||
        name == "fp" || name == "lr") return 64;
    return 0;
}

static void populate_detail(csh handle, const cs_insn& ci, DisasmInsn& out) {
    out.address = ci.address;
    out.size = ci.size;
    out.id = ci.id;
    out.mnemonic = ci.mnemonic;
    out.op_str = ci.op_str;
    out.is_jump = cs_insn_group(handle, &ci, CS_GRP_JUMP);
    out.is_call = cs_insn_group(handle, &ci, CS_GRP_CALL);
    out.is_ret = cs_insn_group(handle, &ci, CS_GRP_RET);

    if (!ci.detail) return;
    const cs_arm64& arm64 = ci.detail->arm64;
    out.writeback = arm64.writeback;
    out.post_index = arm64.post_index;
    out.is_conditional = arm64.cc != ARM64_CC_INVALID &&
                         arm64.cc != ARM64_CC_AL &&
                         arm64.cc != ARM64_CC_NV;
    out.is_conditional = out.is_conditional ||
                         starts_with(out.mnemonic, "b.") ||
                         out.mnemonic == "cbz" || out.mnemonic == "cbnz" ||
                         out.mnemonic == "tbz" || out.mnemonic == "tbnz";
    out.operand_count = std::min<uint8_t>(arm64.op_count,
                                          static_cast<uint8_t>(out.operands.size()));

    for (uint8_t i = 0; i < out.operand_count; ++i) {
        const cs_arm64_op& src = arm64.operands[i];
        DisasmOperand& dst = out.operands[i];
        dst.access = src.access;
        switch (src.type) {
            case ARM64_OP_REG:
                dst.type = DisasmOperandType::Reg;
                dst.reg = canonical_reg_name(handle, src.reg);
                dst.reg_width_bits = register_width_bits(handle, src.reg);
                break;
            case ARM64_OP_IMM:
            case ARM64_OP_CIMM:
                dst.type = DisasmOperandType::Imm;
                dst.imm = src.imm;
                break;
            case ARM64_OP_MEM:
                dst.type = DisasmOperandType::Mem;
                dst.mem_base = canonical_reg_name(handle, src.mem.base);
                dst.mem_index = canonical_reg_name(handle, src.mem.index);
                dst.mem_disp = src.mem.disp;
                break;
            default:
                break;
        }
    }
}

A64StatsEx Arm64DisasmEngine::analyze_text(const uint8_t* data, size_t size, uint64_t base_addr) {
    A64StatsEx s{};
    if (!impl_ || !impl_->inited || !data || size == 0) return s;

    cs_insn* insn = cs_malloc(impl_->handle);
    if (!insn) return s;

    const uint8_t* code = data;
    size_t remaining = size;
    uint64_t address = base_addr;

    // Streaming disassembly avoids retaining cs_detail for every instruction in a
    // large SO. This changes peak memory from O(.text size) to O(1).
    while (remaining >= 4) {
        const uint8_t* before_code = code;
        const size_t before_remaining = remaining;
        const uint64_t before_address = address;
        if (!cs_disasm_iter(impl_->handle, &code, &remaining, &address, insn)) {
            // AArch64 instructions are 4-byte aligned. Inline data or an
            // intentionally invalid word must not truncate statistics for the
            // entire remainder of the executable region.
            code = before_code + 4;
            remaining = before_remaining - 4;
            address = before_address + 4;
            continue;
        }
        const cs_insn& ci = *insn;
        std::string m = ci.mnemonic;
        s.total_insn++;

        bool is_jump = cs_insn_group(impl_->handle, &ci, CS_GRP_JUMP);
        bool is_call = cs_insn_group(impl_->handle, &ci, CS_GRP_CALL);
        bool is_ret  = cs_insn_group(impl_->handle, &ci, CS_GRP_RET);

        if (is_jump) s.jump++;
        if (is_call) s.call++;
        if (is_ret)  s.ret++;

        if (m == "b.eq" || m == "b.ne" || m == "b.lt" || m == "b.le" ||
            m == "b.gt" || m == "b.ge" || m == "b.cs" || m == "b.cc" ||
            m == "b.mi" || m == "b.pl" || m == "b.vs" || m == "b.vc" ||
            m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") {
            s.cond_jump++;
        }

        if (m == "br" || m == "blr") {
            s.indirect_jump++;
        }

        if (starts_with(m, "ldr") || m == "ldp" || m == "ldur" || m == "ldxr" || m == "ldaxr") {
            s.load++;
        }

        if (starts_with(m, "str") || m == "stp" || m == "stur" || m == "stxr" || m == "stlxr") {
            s.store++;
        }

        if (m == "add" || m == "sub" || m == "subs" || m == "adc" || m == "sbc" ||
            m == "mul" || m == "madd" || m == "msub" || m == "udiv" || m == "sdiv" ||
            m == "neg" || m == "cmp" || m == "cmn") {
            s.arithmetic++;
        }

        if (m == "and" || m == "ands" || m == "orr" || m == "eor" ||
            m == "bic" || m == "orn" || m == "eon" || m == "tst") {
            s.logical++;
        }

        if (m == "cmp" || m == "cmn" || m == "tst") {
            s.compare++;
        }
    }

    cs_free(insn, 1);
    return s;
}

std::vector<DisasmLine> Arm64DisasmEngine::disasm_preview(const uint8_t* data,
                                                          size_t size,
                                                          uint64_t base_addr,
                                                          size_t max_insn) {
    std::vector<DisasmLine> out;
    if (!impl_ || !impl_->inited || !data || size == 0) return out;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(impl_->handle, data, size, base_addr, max_insn, &insn);
    if (count == 0) return out;

    size_t n = (count < max_insn) ? count : max_insn;
    out.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        DisasmLine line;
        line.address = insn[i].address;
        line.mnemonic = insn[i].mnemonic;
        line.op_str = insn[i].op_str;
        out.push_back(std::move(line));
    }

    cs_free(insn, count);
    return out;
}

std::vector<DisasmInsn> Arm64DisasmEngine::disasm_all(const uint8_t* data,
                                                      size_t size,
                                                      uint64_t base_addr,
                                                      size_t max_insn) {
    std::vector<DisasmInsn> out;
    if (!impl_ || !impl_->inited || !data || size == 0) return out;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(impl_->handle, data, size, base_addr, max_insn, &insn);
    if (count == 0) return out;

    size_t n = count;
    if (max_insn > 0) n = std::min(count, max_insn);

    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        DisasmInsn di;
        populate_detail(impl_->handle, insn[i], di);
        out.push_back(std::move(di));
    }

    cs_free(insn, count);
    return out;
}

std::vector<DisasmInsn> Arm64DisasmEngine::disasm_aligned_resilient(const uint8_t* data,
                                                                    size_t size,
                                                                    uint64_t base_addr,
                                                                    size_t max_insn) {
    std::vector<DisasmInsn> out;
    if (!impl_ || !impl_->inited || !data || size < 4) return out;

    cs_insn* insn = cs_malloc(impl_->handle);
    if (!insn) return out;

    const uint8_t* code = data;
    size_t remaining = size;
    uint64_t address = base_addr;
    while (remaining >= 4 && (max_insn == 0 || out.size() < max_insn)) {
        const uint8_t* before_code = code;
        size_t before_remaining = remaining;
        uint64_t before_address = address;

        if (cs_disasm_iter(impl_->handle, &code, &remaining, &address, insn)) {
            DisasmInsn decoded;
            populate_detail(impl_->handle, *insn, decoded);
            out.push_back(std::move(decoded));
            continue;
        }

        // AArch64 is fixed-width. Skip an undecodable word so an inline data
        // island cannot hide a valid dispatcher later in the candidate range.
        code = before_code + 4;
        remaining = before_remaining - 4;
        address = before_address + 4;
    }

    cs_free(insn, 1);
    return out;
}
