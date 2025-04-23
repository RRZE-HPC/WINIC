#include "Templates.h"

#include "llvm/Support/raw_ostream.h" // for errs, raw_fd_ostream
#include <set>                        // for set
#include <stdlib.h>                   // for exit, EXIT_FAILURE

Template::Template(string Prefix, string PreInit, string PostInit, string PreLoop, string BeginLoop,
                   string EndLoop, string PostLoop, string Suffix,
                   std::vector<std::pair<string, string>> RegInitCode,
                   std::set<string> UsedRegisters)
    : prefix(std::move(Prefix)), preInit(std::move(PreInit)), postInit(std::move(PostInit)),
      preLoop(std::move(PreLoop)), beginLoop(std::move(BeginLoop)), endLoop(std::move(EndLoop)),
      postLoop(std::move(PostLoop)), suffix(std::move(Suffix)), regInitTemplates(RegInitCode),
      usedRegisters(std::move(UsedRegisters)) {
    // for readability of this file strings have a leading newline
    // this gets removed here
    trimLeadingNewline(this->prefix);
    trimLeadingNewline(this->preInit);
    trimLeadingNewline(this->postInit);
    trimLeadingNewline(this->preLoop);
    trimLeadingNewline(this->beginLoop);
    trimLeadingNewline(this->endLoop);
    trimLeadingNewline(this->postLoop);
    trimLeadingNewline(this->suffix);
}

void Template::trimLeadingNewline(string &Str) {
    if (!Str.empty() && Str[0] == '\n') {
        Str.erase(0, 1);
    }
}

Template X86Template = {
    R"(
#define N edi
#define i r8d

.intel_syntax noprefix
.text
)",
    R"(
.globl init
.type init, @function
.align 32
init:
)",
    R"(
    ret
.size init, .-init
)",
    R"(

.globl functionName
.type functionName, @function
.align 32
functionName:
        push      rbp
        mov       rbp, rsp

        xor       i, i
        test      N, N

)",
    R"(
        jle       done_functionName
loop_functionName:
        inc       i
)",
    R"(
        cmp       i, N
        jl        loop_functionName
done_functionName:
)",
    R"(
        mov  rsp, rbp
        pop rbp
        ret
.size functionName, .-functionName
)",
    R"(
.section .note.GNU-stack,"",@progbits
)",
    std::vector<std::pair<string, string>>{
        // will be checked in order, default must be last and gets used if no other apply
        // map to "None" if the register type should not be initialized.
        // every instance of "reg" will be replaced by the register to initialize, every instance of
        // "imm" will be replaced by the immediate value to initialize it with
        {"xmm", "\tmov eax, imm\n\tmovd reg, eax"},
        {"ymm", "\tmov eax, imm\n\tmovd xmm0, eax\n\tvbroadcastss reg, xmm0"},
        {"zmm", "\tmov eax, imm\n\tmovd xmm0, eax\n\tvbroadcastss reg, xmm0"},
        {"mm", "\tmov eax, imm\n\tmovd xmm0, eax\n\tvbroadcastss reg, xmm0"},
        {"k", "None"},
        {"default", "mov reg, imm"}},
    {"edi", "r8d", "rbp", "rsp"}};

Template AArch64Template = {
    R"(
#define N x0

.text

)",
    R"(
.globl functionName
.type functionName, @function
.align 32
functionName:
)",
    R"(
    ret
.size functionName, .-functionName
)",
    R"(

.globl functionName
.type functionName, @function
.align 2
functionName:
        # push callee-save registers onto stack
        sub     sp, sp, #64
        st1     {v8.2d, v9.2d, v10.2d, v11.2d}, [sp]
        sub     sp, sp, #64
        st1     {v12.2d, v13.2d, v14.2d, v15.2d}, [sp]
        sub     sp, sp, #64
        st1     {v16.2d, v17.2d, v18.2d, v19.2d}, [sp]
        sub     sp, sp, #64
        st1     {v20.2d, v21.2d, v22.2d, v23.2d}, [sp]
        sub     sp, sp, #64
        st1     {v24.2d, v25.2d, v26.2d, v27.2d}, [sp]
        sub     sp, sp, #64
        st1     {v28.2d, v29.2d, v30.2d, v31.2d}, [sp]
        stp     x19, x20, [sp, -96]!
        stp     x21, x22, [sp, 16]
        stp     x23, x24, [sp, 32]
        stp     x25, x26, [sp, 48]
        stp     x27, x28, [sp, 64]
        stp     x29, x30, [sp, 80]

        mov     x4, N
)",
    R"(
loop_functionName:
)",
    R"(
        subs      x4, x4, #1
        bne       loop_functionName
done_functionName:
)",
    R"(
        # pop callee-save registers from stack
        ldp     x19, x20, [sp]
        ldp     x21, x22, [sp, 16]
        ldp     x23, x24, [sp, 32]
        ldp     x25, x26, [sp, 48]
        ldp     x27, x28, [sp, 64]
        ldp     x29, x30, [sp, 80]
        add     sp, sp, #96
        ld1     {v28.2d, v29.2d, v30.2d, v31.2d}, [sp], #64
        ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [sp], #64
        ld1     {v20.2d, v21.2d, v22.2d, v23.2d}, [sp], #64
        ld1     {v16.2d, v17.2d, v18.2d, v19.2d}, [sp], #64
        ld1     {v12.2d, v13.2d, v14.2d, v15.2d}, [sp], #64
        ld1     {v8.2d, v9.2d, v10.2d, v11.2d}, [sp], #64

        ret

.size functionName, .-functionName
)",
    R"(
    section .note.GNU-stack noexec
)",
    std::vector<std::pair<string, string>>{
        // TODO
        {"default", "mov reg, 0x40000000"},
        {"xmm", "mov eax, 0x40000000\nmovd reg, eax"},
        {"ymm", "mov eax, 0x40000000\nmovd xmm0, eax\nvbroadcastss reg, xmm0"},
        {"zmm", "mov eax, 0x40000000\nmovd xmm0, eax\nvbroadcastss reg, xmm0"},
        {"mm", "mov eax, 0x40000000\nmovd xmm0, eax\nvbroadcastss reg, xmm0"}},
    {"x0", "x4"}};

Template getTemplate(llvm::Triple::ArchType Arch) {
    switch (Arch) {
    case llvm::Triple::x86_64: {
        return X86Template;
    }
    case llvm::Triple::aarch64: {
        return AArch64Template;
    }
    default:
        llvm::errs() << "Tried to get a template for an unsupported arch, this should not happen\n";
        exit(EXIT_FAILURE);
    }
}
