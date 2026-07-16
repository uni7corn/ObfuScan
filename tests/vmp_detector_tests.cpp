#include "vmp_detector.h"

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

void expect(bool condition, const std::string& message);

DisasmOperand reg(const std::string& name) {
    DisasmOperand op;
    op.type = DisasmOperandType::Reg;
    op.reg = name;
    if (op.reg.size() >= 2 && op.reg[0] == 'w') {
        op.reg[0] = 'x';
        op.reg_width_bits = 32;
    } else if (!op.reg.empty() && op.reg[0] == 'x') {
        op.reg_width_bits = 64;
    }
    return op;
}

DisasmOperand imm(int64_t value) {
    DisasmOperand op;
    op.type = DisasmOperandType::Imm;
    op.imm = value;
    return op;
}

DisasmOperand mem(const std::string& base,
                  const std::string& index = "",
                  int32_t displacement = 0) {
    DisasmOperand op;
    op.type = DisasmOperandType::Mem;
    op.mem_base = base;
    op.mem_index = index;
    op.mem_disp = displacement;
    return op;
}

DisasmInsn instruction(uint64_t address,
                       const std::string& mnemonic,
                       std::initializer_list<DisasmOperand> operands = {}) {
    DisasmInsn ins;
    ins.address = address;
    ins.size = 4;
    ins.mnemonic = mnemonic;
    ins.operand_count = static_cast<uint8_t>(operands.size());
    size_t i = 0;
    for (const auto& operand : operands) ins.operands[i++] = operand;
    return ins;
}

void append_classic_dispatch(std::vector<DisasmInsn>& out,
                             uint64_t& pc,
                             const std::string& vip = "x19") {
    const uint64_t begin = pc;
    out.push_back(instruction(pc, "ldrb", {reg("x8"), mem(vip)})); pc += 4;
    out.push_back(instruction(pc, "add", {reg(vip), reg(vip), imm(1)})); pc += 4;
    out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
    out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
    out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22", "", 0)})); pc += 4;
    out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
    auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
    back.is_jump = true;
    back.is_conditional = true;
    out.push_back(back); pc += 4;
    auto branch = instruction(pc, "br", {reg("x17")});
    branch.is_jump = true;
    out.push_back(branch); pc += 4;
}

void append_call_threaded_dispatch(std::vector<DisasmInsn>& out,
                                   uint64_t& pc,
                                   const std::string& vip = "x19") {
    const uint64_t begin = pc;
    out.push_back(instruction(pc, "ldrb", {reg("x8"), mem(vip)})); pc += 4;
    out.push_back(instruction(pc, "add", {reg(vip), reg(vip), imm(1)})); pc += 4;
    out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
    out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
    out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22", "", 0)})); pc += 4;
    out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
    auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
    back.is_jump = true;
    back.is_conditional = true;
    out.push_back(back); pc += 4;
    auto call = instruction(pc, "blr", {reg("x17")});
    call.is_call = true;
    out.push_back(call); pc += 4;
}

std::vector<DisasmInsn> callback_array_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x6000;
    for (size_t i = 0; i < count; ++i) {
        auto fetch = instruction(pc, "ldr", {reg("x8"), mem("x20")});
        fetch.writeback = true;
        fetch.post_index = true;
        out.push_back(fetch); pc += 4;
        auto call = instruction(pc, "blr", {reg("x8")});
        call.is_call = true;
        out.push_back(call); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> killed_taint_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0xa000;
    for (size_t i = 0; i < count; ++i) {
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "mov", {reg("x8"), reg("x0")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> killed_vip_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0xb000;
    for (size_t i = 0; i < count; ++i) {
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "mov", {reg("x19"), reg("x0")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> relative_handler_table_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0xc000;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t begin = pc;
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
        out.push_back(instruction(pc, "ldrsw", {reg("x10"), mem("x20", "x8")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x17"), reg("x20"), reg("x10")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22", "", 0)})); pc += 4;
        out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
        auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
        back.is_jump = true;
        back.is_conditional = true;
        out.push_back(back); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> shadowed_opcode_fetch_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0xe000;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t begin = pc;
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
        out.push_back(instruction(pc, "ldrb", {reg("x10"), mem("x23")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22", "", 0)})); pc += 4;
        out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
        auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
        back.is_jump = true;
        back.is_conditional = true;
        out.push_back(back); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> multi_fetch_dispatch_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x11000;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t begin = pc;
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
        out.push_back(instruction(pc, "ldrb", {reg("x10"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22", "", 0)})); pc += 4;
        out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
        auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
        back.is_jump = true;
        back.is_conditional = true;
        out.push_back(back); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> word_opcode_dispatch_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x15000;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t begin = pc;
        out.push_back(instruction(pc, "ldr", {reg("w8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(4)})); pc += 4;
        out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22")})); pc += 4;
        out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
        auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
        back.is_jump = true;
        back.is_conditional = true;
        out.push_back(back); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> unreachable_dispatch_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x18000;
    for (size_t i = 0; i < count; ++i) {
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        auto exit = instruction(pc, "b", {imm(static_cast<int64_t>(pc + 12))});
        exit.is_jump = true;
        out.push_back(exit); pc += 4;
        // These instructions are linearly adjacent but unreachable from the
        // opcode fetch above and must form a different basic block.
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> central_dispatcher_with_handler_return() {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x1b000;
    const uint64_t dispatcher = pc;
    out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
    out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
    out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
    out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x8")})); pc += 4;
    auto dispatch = instruction(pc, "br", {reg("x17")});
    dispatch.is_jump = true;
    out.push_back(dispatch); pc += 4;
    out.push_back(instruction(pc, "ldr", {reg("x9"), mem("x22")})); pc += 4;
    out.push_back(instruction(pc, "str", {reg("x9"), mem("x22", "", 8)})); pc += 4;
    auto handler_return = instruction(pc, "b", {imm(static_cast<int64_t>(dispatcher))});
    handler_return.is_jump = true;
    out.push_back(handler_return);
    return out;
}

void append_word(std::vector<uint8_t>& out, uint32_t word) {
    out.push_back(static_cast<uint8_t>(word));
    out.push_back(static_cast<uint8_t>(word >> 8));
    out.push_back(static_cast<uint8_t>(word >> 16));
    out.push_back(static_cast<uint8_t>(word >> 24));
}

void append_encoded_classic_dispatch(std::vector<uint8_t>& out,
                                     uint32_t transfer = 0xd61f0220U) {
    // ldrb w8,[x19]; add x19,x19,#1; eor w8,w8,w21;
    // ldr x17,[x20,x8,lsl#3]; ldr/str VM context; b.ne; br x17
    static const uint32_t words[] = {
        0x39400268U, 0x91000673U, 0x4a150108U, 0xf8687a91U,
        0xf94002c9U, 0xf90006c9U, 0x54ffff41U
    };
    for (uint32_t word : words) append_word(out, word);
    append_word(out, transfer);
}

void test_pointer_authenticated_dispatch_is_scanned() {
    std::vector<uint8_t> rx;
    for (int i = 0; i < 5; ++i) {
        append_encoded_classic_dispatch(rx, 0xd71f0a32U); // braa x17,x18
    }
    std::vector<ExecutableRegionView> regions = {
        {rx.data(), rx.size(), 0x500000, "PT_LOAD[pac]"}
    };
    auto result = analyze_vmp_regions(regions, {});
    expect(result.metrics.raw_indirect_transfers == 5,
           "pointer-authenticated BRAA sites must reach candidate disassembly");
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "BRAA dispatch must retain the same dataflow evidence as BR");
}

void test_default_returns_do_not_consume_candidate_budget() {
    std::vector<uint8_t> rx;
    for (int i = 0; i < 4096; ++i) append_word(rx, 0xd65f03c0U); // ret x30
    for (int i = 0; i < 5; ++i) append_encoded_classic_dispatch(rx);
    std::vector<ExecutableRegionView> regions = {
        {rx.data(), rx.size(), 0x700000, "PT_LOAD[ret-heavy]"}
    };
    auto result = analyze_vmp_regions(regions, {});
    expect(result.metrics.raw_indirect_transfers == 5,
           "ordinary function returns must not consume VMP candidate budget");
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "real dispatchers after return-heavy code must remain visible");
}

std::vector<DisasmInsn> classic_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x1000;
    for (size_t i = 0; i < count; ++i) append_classic_dispatch(out, pc);
    return out;
}

std::vector<DisasmInsn> medium_only_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x28000;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t begin = pc;
        out.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x19")})); pc += 4;
        out.push_back(instruction(pc, "add", {reg("x19"), reg("x19"), imm(1)})); pc += 4;
        out.push_back(instruction(pc, "eor", {reg("x8"), reg("x8"), reg("x21")})); pc += 4;
        // Target loading is real, but deliberately independent from the
        // fetched opcode: this is medium topology, not closed VM dataflow.
        out.push_back(instruction(pc, "ldr", {reg("x17"), mem("x20", "x9")})); pc += 4;
        out.push_back(instruction(pc, "ldr", {reg("x10"), mem("x22")})); pc += 4;
        out.push_back(instruction(pc, "str", {reg("x10"), mem("x22", "", 8)})); pc += 4;
        auto back = instruction(pc, "b.ne", {imm(static_cast<int64_t>(begin))});
        back.is_jump = true;
        back.is_conditional = true;
        out.push_back(back); pc += 4;
        auto branch = instruction(pc, "br", {reg("x17")});
        branch.is_jump = true;
        out.push_back(branch); pc += 4;
    }
    return out;
}

std::vector<DisasmInsn> call_threaded_stream(size_t count) {
    std::vector<DisasmInsn> out;
    uint64_t pc = 0x4000;
    for (size_t i = 0; i < count; ++i) append_call_threaded_dispatch(out, pc);
    return out;
}

void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << '\n';
        std::exit(1);
    }
}

void test_overlapping_window_regression() {
    auto result = analyze_vmp_instruction_stream(classic_stream(1), {});
    expect(result.metrics.strong_candidates == 1,
           "one indirect branch must produce exactly one strong candidate");
    expect(result.metrics.unique_candidates == 1,
           "overlapping instruction neighborhoods must not duplicate a candidate");
    expect(!result.possible, "one local pattern is insufficient for a VMP verdict");
}

void test_explicit_thunk_range_exclusion() {
    VmpAnalysisContext context;
    context.excluded_thunk_ranges.push_back({0x101c, 0x1020});
    auto result = analyze_vmp_instruction_stream(classic_stream(5), context);
    expect(result.metrics.excluded_thunk_sites == 1,
           "an exact excluded branch range must be observable in scan metrics");
    expect(result.metrics.strong_candidates == 4,
           "excluding one thunk branch must not hide adjacent real candidates");
}

void test_classic_register_dispatch() {
    auto result = analyze_vmp_instruction_stream(classic_stream(5), {});
    expect(result.metrics.strong_candidates == 5,
           "five independent dispatch sites should remain five candidates");
    expect(result.metrics.dominant_vip_sites == 5,
           "independent sites should share the same VPC/VIP register");
    expect(result.structure_score >= 0.80,
           "closed opcode-to-target dataflow should produce strong VM structure evidence");
    expect(result.possible && result.outcome == "LIKELY_VMP",
           "a repeated closed dispatch dataflow should be classified as likely VMP");
}

void test_call_threaded_dispatch() {
    auto result = analyze_vmp_instruction_stream(call_threaded_stream(5), {});
    expect(result.metrics.call_dispatch_candidates == 5,
           "call-threaded handler fetches must be retained instead of penalized");
    expect(result.profile == "CALL_THREADED",
           "call-threaded dispatch should have its own profile");
    expect(result.possible,
           "repeated closed opcode-to-handler dataflow plus BLR should pass the structural gate");
}

void test_vtable_hard_negative() {
    std::vector<DisasmInsn> stream;
    uint64_t pc = 0x7000;
    for (int i = 0; i < 12; ++i) {
        stream.push_back(instruction(pc, "ldr", {reg("x8"), mem("x0")})); pc += 4;
        stream.push_back(instruction(pc, "ldr", {reg("x9"), mem("x8", "", 16)})); pc += 4;
        auto call = instruction(pc, "blr", {reg("x9")});
        call.is_call = true;
        stream.push_back(call); pc += 4;
    }
    auto result = analyze_vmp_instruction_stream(stream, {});
    expect(result.metrics.unique_candidates == 0,
           "ordinary object-vtable-BLR chains must not become VM candidates");
    expect(!result.possible && result.structure_score < 0.20,
           "vtable-heavy C++ is a hard negative");
}

void test_callback_array_hard_negative() {
    auto result = analyze_vmp_instruction_stream(callback_array_stream(12), {});
    expect(result.metrics.strong_candidates == 0,
           "a BLR callback array without VM state or a closed loop is not strong evidence");
    expect(!result.possible,
           "iterating and calling function pointers must not be classified as likely VMP");
    expect(result.alternative_explanation == "function-pointer callback/destructor loop",
           "the callback-loop alternative must be visible to users");
}

void test_wx_alias_self_clobber_regression() {
    std::vector<DisasmInsn> stream;
    uint64_t pc = 0x8000;
    for (int i = 0; i < 8; ++i) {
        stream.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x8")})); pc += 4;
        stream.push_back(instruction(pc, "add", {reg("x8"), reg("x8"), imm(1)})); pc += 4;
        stream.push_back(instruction(pc, "ldr", {reg("x9"), mem("x20", "x8")})); pc += 4;
        auto branch = instruction(pc, "br", {reg("x9")});
        branch.is_jump = true;
        stream.push_back(branch); pc += 4;
    }
    auto result = analyze_vmp_instruction_stream(stream, {});
    expect(result.metrics.strong_candidates == 0,
           "ldrb w8,[x8] clobbers x8 and cannot preserve it as a VPC");
    expect(!result.possible,
           "W/X aliases must not create a synthetic opcode-to-handler dataflow");
}

void test_register_overwrite_kills_opcode_taint() {
    auto result = analyze_vmp_instruction_stream(killed_taint_stream(6), {});
    expect(result.metrics.strong_candidates == 0,
           "overwriting the opcode register must kill its dataflow provenance");
    expect(!result.possible,
           "an unrelated table lookup after a register overwrite is not a VM dispatcher");
}

void test_vip_overwrite_kills_fetch_provenance() {
    auto result = analyze_vmp_instruction_stream(killed_vip_stream(6), {});
    expect(result.metrics.strong_candidates == 0,
           "overwriting VPC before an add must kill fetch-pointer provenance");
    expect(!result.possible,
           "advancing an unrelated replacement pointer is not VPC evolution");
}

void test_relative_handler_offset_table() {
    auto result = analyze_vmp_instruction_stream(relative_handler_table_stream(5), {});
    expect(result.metrics.table_linked_candidates == 5,
           "ldrsw plus add should remain linked to the opcode table index");
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "relative-offset handler tables should be recognized as closed dispatch dataflow");
}

void test_nearer_flag_load_does_not_shadow_opcode_fetch() {
    auto result = analyze_vmp_instruction_stream(shadowed_opcode_fetch_stream(5), {});
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "a non-advancing flag load must not hide an earlier closed opcode fetch");
}

void test_advanced_operand_fetch_does_not_shadow_opcode() {
    auto result = analyze_vmp_instruction_stream(multi_fetch_dispatch_stream(5), {});
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "an advanced operand fetch must not shadow the opcode feeding the handler table");
}

void test_word_sized_opcode_fetch() {
    auto result = analyze_vmp_instruction_stream(word_opcode_dispatch_stream(5), {});
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "32-bit LDR opcode fetches must close the same VPC-to-handler dataflow");
}

void test_unreachable_code_cannot_complete_dataflow() {
    auto result = analyze_vmp_instruction_stream(unreachable_dispatch_stream(6), {});
    expect(result.metrics.strong_candidates == 0,
           "an unconditional branch must terminate opcode provenance");
    expect(!result.possible,
           "linearly adjacent but unreachable handler loads are not VM dispatchers");
}

void test_central_dispatcher_handler_return_edge() {
    VmpAnalysisContext context;
    context.vmp_metadata_marker = true;
    auto result = analyze_vmp_instruction_stream(
        central_dispatcher_with_handler_return(), context);
    expect(result.metrics.strong_candidates == 1,
           "one central dispatcher must remain one deduplicated candidate");
    expect(result.structure_score >= 0.70 && result.possible,
           "a handler edge returning to a closed dispatcher plus protection intent is sufficient");
}

void test_switch_jump_table_hard_negative() {
    std::vector<DisasmInsn> stream;
    uint64_t pc = 0x9000;
    for (int i = 0; i < 8; ++i) {
        stream.push_back(instruction(pc, "ldrb", {reg("x8"), mem("x20", "x0")})); pc += 4;
        stream.push_back(instruction(pc, "adr", {reg("x9"), imm(static_cast<int64_t>(pc + 32))})); pc += 4;
        stream.push_back(instruction(pc, "add", {reg("x9"), reg("x9"), reg("x8")})); pc += 4;
        auto branch = instruction(pc, "br", {reg("x9")});
        branch.is_jump = true;
        stream.push_back(branch); pc += 4;
    }
    auto result = analyze_vmp_instruction_stream(stream, {});
    expect(result.metrics.strong_candidates == 0,
           "an ordinary AArch64 switch table has no evolving VPC");
    expect(!result.possible,
           "switch jump-table shapes must be treated as an alternative explanation");
}

void test_legitimate_interpreter_separate_class() {
    VmpAnalysisContext context;
    context.known_runtime = true;
    context.runtime_evidence_classes = 2;
    context.known_runtime_name = "QuickJS bytecode runtime";
    auto result = analyze_vmp_instruction_stream(classic_stream(5), context);
    expect(result.structure_score >= 0.80,
           "a legitimate interpreter can have genuine VM structure");
    expect(!result.possible && result.outcome == "VM_LIKE_INTERPRETER",
           "VM structure alone must not imply protection intent");
    expect(result.alternative_explanation == "QuickJS bytecode runtime",
           "the alternative explanation must be exposed");
}

void test_confirmed_runtime_never_falls_through_to_suspicious() {
    VmpAnalysisContext context;
    context.known_runtime = true;
    context.runtime_evidence_classes = 2;
    context.known_runtime_name = "confirmed FFmpeg/media runtime";
    auto result = analyze_vmp_instruction_stream(classic_stream(1), context);
    expect(result.structure_score >= 0.55,
           "the fixture must remain structurally suspicious without an alternative");
    expect(!result.possible && result.outcome == "VM_LIKE_INTERPRETER",
           "a confirmed legitimate runtime without protection coexistence must not remain suspicious");
}

void test_weak_runtime_hint_is_not_global_veto() {
    VmpAnalysisContext context;
    context.runtime_evidence_classes = 1;
    context.known_runtime_name = "weak basename-only runtime hint";
    auto result = analyze_vmp_instruction_stream(classic_stream(5), context);
    expect(result.outcome == "SUSPICIOUS_VM_STRUCTURE" && !result.possible,
           "one runtime evidence class may defer a high verdict but must not relabel the whole SO as an interpreter");
    expect(result.alternative_explanation == "weak basename-only runtime hint",
           "the weak competing explanation should remain visible for review");
}

void test_confirmed_runtime_can_coexist_with_protected_vmp() {
    VmpAnalysisContext context;
    context.known_runtime = true;
    context.runtime_evidence_classes = 2;
    context.known_runtime_name = "confirmed embedded interpreter";
    context.vmp_metadata_marker = true;
    auto result = analyze_vmp_instruction_stream(classic_stream(5), context);
    expect(result.possible && result.outcome == "LIKELY_VMP",
           "protection-specific metadata plus decisive closed dataflow must override a confirmed runtime alternative");
}

void test_medium_only_structure_requires_independent_intent() {
    auto ordinary = analyze_vmp_instruction_stream(medium_only_stream(12), {});
    expect(ordinary.metrics.strong_candidates == 0 &&
           ordinary.metrics.medium_candidates > 0,
           "the fixture must exercise medium-only dispatch-like structure");
    expect(ordinary.outcome == "NO_VMP_EVIDENCE" && !ordinary.possible,
           "medium-only topology without protection intent is common switch/runtime noise");

    VmpAnalysisContext generic_loader_context;
    generic_loader_context.custom_linker_marker = true;
    auto generic_loader = analyze_vmp_instruction_stream(
        medium_only_stream(12), generic_loader_context);
    expect(generic_loader.outcome == "NO_VMP_EVIDENCE" && !generic_loader.possible,
           "a generic loader marker alone must not promote medium-only topology");

    VmpAnalysisContext protected_context;
    protected_context.vmp_metadata_marker = true;
    auto protected_result = analyze_vmp_instruction_stream(
        medium_only_stream(12), protected_context);
    expect(protected_result.outcome == "SUSPICIOUS_VM_STRUCTURE" &&
           !protected_result.possible,
           "independent protection metadata may retain medium-only structure for review");
}

void test_control_flow_obfuscation_is_an_alternative() {
    VmpAnalysisContext context;
    context.control_flow_obfuscation_likely = true;
    auto result = analyze_vmp_instruction_stream(classic_stream(1), context);
    expect(result.metrics.strong_candidates == 1,
           "the competing explanation test must retain its isolated dataflow site");
    expect(result.outcome == "NO_VMP_EVIDENCE" && !result.possible,
           "one site inside an independent packer/CFF profile must not become VMP suspicion");
    expect(result.alternative_explanation ==
               "control-flow obfuscation or packer state machine",
           "the competing control-flow explanation must remain visible");
}

void test_known_non_vm_framework_sparse_dispatch_is_not_vmp() {
    VmpAnalysisContext context;
    context.known_non_vm_framework = true;
    context.custom_linker_marker = true;
    context.custom_linker_likely = true;
    auto result = analyze_vmp_instruction_stream(classic_stream(2), context);
    expect(result.metrics.strong_candidates == 2,
           "the framework hard negative must retain its sparse local dataflow");
    expect(!result.possible && result.outcome == "SUSPICIOUS_VM_STRUCTURE",
           "a known non-VM framework plus generic loader markers may remain reviewable but must not become a VMP provider");
}

void test_protection_metadata_requires_structure() {
    VmpAnalysisContext context;
    context.vmp_metadata_marker = true;
    auto positive = analyze_vmp_instruction_stream(classic_stream(3), context);
    expect(positive.possible,
           "protection metadata may strengthen multiple independent structural candidates");

    auto central = analyze_vmp_instruction_stream(classic_stream(1), context);
    expect(central.possible,
           "one closed central dispatcher plus protection intent should be sufficient");

    auto negative = analyze_vmp_instruction_stream(std::vector<DisasmInsn>{}, context);
    expect(!negative.possible,
           "a marker string without executable structure must never create a VMP verdict");
}

void test_packing_is_inconclusive_not_negative() {
    VmpAnalysisContext context;
    context.code_obscured_by_packing = true;
    auto result = analyze_vmp_instruction_stream({}, context);
    expect(result.outcome == "INCONCLUSIVE_PACKED",
           "hidden runtime code must be reported as inconclusive, not as no evidence");
    expect(result.confidence == "UNKNOWN", "inconclusive packing must not claim confidence");

    auto visible_stub = analyze_vmp_instruction_stream(classic_stream(5), context);
    expect(visible_stub.observable,
           "visible executable stub bytes remain observable even when a payload is packed");
    expect(!visible_stub.possible && visible_stub.outcome == "INCONCLUSIVE_PACKED",
           "packing alone must not turn static stub coincidences into high-confidence VMP");
}

void test_decode_budget_is_fair_across_rx_regions() {
    std::vector<uint8_t> first_rx(17 * 1024 * 1024, 0x1f);
    // NOP fill plus sparse BR x0 sites creates more than one region's fair
    // decode share without allocating an unbounded offset vector.
    for (size_t offset = 0; offset + 4 <= first_rx.size(); offset += 256) {
        first_rx[offset + 0] = 0x00;
        first_rx[offset + 1] = 0x00;
        first_rx[offset + 2] = 0x1f;
        first_rx[offset + 3] = 0xd6;
    }
    std::vector<uint8_t> second_rx;
    for (int i = 0; i < 5; ++i) append_encoded_classic_dispatch(second_rx);
    std::vector<ExecutableRegionView> regions = {
        {first_rx.data(), first_rx.size(), 0x100000, "PT_LOAD[huge-first]"},
        {second_rx.data(), second_rx.size(), 0x4000000, "PT_LOAD[late-vmp]"}
    };
    auto result = analyze_vmp_regions(regions, {});
    expect(result.scan_truncated,
           "the pathological first RX segment should report its decode budget limit");
    expect(result.metrics.strong_candidates == 5 && result.possible,
           "a large first RX segment must not starve a later dispatcher segment");
}

void test_late_second_rx_region_is_scanned() {
    std::vector<uint8_t> first_rx(4096, 0);
    std::vector<uint8_t> second_rx;
    second_rx.reserve(320 * 1024);
    while (second_rx.size() < 300 * 1024) append_word(second_rx, 0xd503201fU);
    append_word(second_rx, 0xffffffffU); // deliberately undecodable slot
    for (int i = 0; i < 5; ++i) append_encoded_classic_dispatch(second_rx);

    std::vector<ExecutableRegionView> regions = {
        {first_rx.data(), first_rx.size(), 0x1000, "PT_LOAD[0]"},
        {second_rx.data(), second_rx.size(), 0x900000, "PT_LOAD[1]"}
    };
    auto result = analyze_vmp_regions(regions, {});
    expect(result.coverage == 1.0,
           "all candidate sites in both executable segments should be analyzed");
    expect(result.metrics.strong_candidates == 5,
           "a dispatcher beyond the old 256 KiB boundary must remain visible");
    expect(result.possible && result.outcome == "LIKELY_VMP",
           "closed dispatchers in a second RX segment should classify as likely VMP");
}

} // namespace

int main() {
    test_overlapping_window_regression();
    test_explicit_thunk_range_exclusion();
    test_classic_register_dispatch();
    test_call_threaded_dispatch();
    test_vtable_hard_negative();
    test_callback_array_hard_negative();
    test_wx_alias_self_clobber_regression();
    test_register_overwrite_kills_opcode_taint();
    test_vip_overwrite_kills_fetch_provenance();
    test_relative_handler_offset_table();
    test_nearer_flag_load_does_not_shadow_opcode_fetch();
    test_advanced_operand_fetch_does_not_shadow_opcode();
    test_word_sized_opcode_fetch();
    test_unreachable_code_cannot_complete_dataflow();
    test_central_dispatcher_handler_return_edge();
    test_switch_jump_table_hard_negative();
    test_legitimate_interpreter_separate_class();
    test_confirmed_runtime_never_falls_through_to_suspicious();
    test_weak_runtime_hint_is_not_global_veto();
    test_confirmed_runtime_can_coexist_with_protected_vmp();
    test_medium_only_structure_requires_independent_intent();
    test_control_flow_obfuscation_is_an_alternative();
    test_known_non_vm_framework_sparse_dispatch_is_not_vmp();
    test_protection_metadata_requires_structure();
    test_packing_is_inconclusive_not_negative();
    test_late_second_rx_region_is_scanned();
    test_decode_budget_is_fair_across_rx_regions();
    test_pointer_authenticated_dispatch_is_scanned();
    test_default_returns_do_not_consume_candidate_budget();
    std::cout << "[PASS] vmp_detector_tests\n";
    return 0;
}
