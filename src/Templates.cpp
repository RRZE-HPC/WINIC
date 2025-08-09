#include "Templates.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include <set>
#include <stdlib.h>

namespace winic {

Template::Template(string Prefix, string PreInit, string PostInit, string PreLoop, string BeginLoop,
                   string EndLoop, string PostLoop, string Suffix, std::set<string> UsedRegisters)
    : prefix(std::move(Prefix)), preInit(std::move(PreInit)), postInit(std::move(PostInit)),
      preLoop(std::move(PreLoop)), beginLoop(std::move(BeginLoop)), endLoop(std::move(EndLoop)),
      postLoop(std::move(PostLoop)), suffix(std::move(Suffix)),
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
)", {"edi", "r8d", "rbp", "rsp"}};

Template AArch64Template = {
    R"(
#define N x0

.text

)",
    R"(
.globl functionName
.type functionName, @function
.align 2
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
)", {"x4"}};

Template RISCVTemplate = {
    R"(
#define N x0

.section .text

)",
    R"(
.align 4
.globl functionName
.type functionName, @function
functionName:
    # push callee-save registers onto stack
    addi    sp, sp, -12*8         # Make space for 12 registers (s0–s11), 8 bytes each
    sd      s0,  0(sp)
    sd      s1,  8(sp)
    sd      s2, 16(sp)
    sd      s3, 24(sp)
    sd      s4, 32(sp)
    sd      s5, 40(sp)
    sd      s6, 48(sp)
    sd      s7, 56(sp)
    sd      s8, 64(sp)
    sd      s9, 72(sp)
    sd      s10, 80(sp)
    sd      s11, 88(sp)
    li a1, 4                      # Set number of elements (VL=4)
    vsetvli t0, a1, e32, m1, ta, ma  # Configure vector length (VL=4), 32-bit element size, LMUL=1
)",
    R"(
    ld      s0,  0(sp)
    ld      s1,  8(sp)
    ld      s2, 16(sp)
    ld      s3, 24(sp)
    ld      s4, 32(sp)
    ld      s5, 40(sp)
    ld      s6, 48(sp)
    ld      s7, 56(sp)
    ld      s8, 64(sp)
    ld      s9, 72(sp)
    ld      s10, 80(sp)
    ld      s11, 88(sp)
    addi    sp, sp, 12*8         # Restore stack pointer
    ret
.size functionName, .-functionName
)",
    R"(

.align 4
.globl functionName
.type functionName, @function
functionName:
    # push callee-save registers onto stack
    addi    sp, sp, -12*8         # Make space for 12 registers (s0–s11), 8 bytes each
    sd      s0,  0(sp)
    sd      s1,  8(sp)
    sd      s2, 16(sp)
    sd      s3, 24(sp)
    sd      s4, 32(sp)
    sd      s5, 40(sp)
    sd      s6, 48(sp)
    sd      s7, 56(sp)
    sd      s8, 64(sp)
    sd      s9, 72(sp)
    sd      s10, 80(sp)
    sd      s11, 88(sp)
    li a1, 4                      # Set number of elements (VL=4)
    vsetvli t0, a1, e32, m1, ta, ma  # Configure vector length (VL=4), 32-bit element size, LMUL=1

    li      t0, 0               # i = 0
    mv      t1, a0

    blez    t1, done_functionName

)",
    R"(
loop_functionName:
    addi    t0, t0, 1           # i++
)",
    R"(
        blt     t0, t1, loop_functionName
done_functionName:
)",
    R"(
    # pop callee-save registers from stack
    ld      s0,  0(sp)
    ld      s1,  8(sp)
    ld      s2, 16(sp)
    ld      s3, 24(sp)
    ld      s4, 32(sp)
    ld      s5, 40(sp)
    ld      s6, 48(sp)
    ld      s7, 56(sp)
    ld      s8, 64(sp)
    ld      s9, 72(sp)
    ld      s10, 80(sp)
    ld      s11, 88(sp)
    addi    sp, sp, 12*8         # Restore stack pointer
    ret

.size functionName, .-functionName
)",
    R"(
)", {"x5", "x6", "x7", "x10"}}; // t0, t1, t2, a0 (can't use abi names here)

Template getTemplate(llvm::Triple::ArchType Arch) {
    switch (Arch) {
    case llvm::Triple::x86_64: {
        return X86Template;
    }
    case llvm::Triple::aarch64: {
        return AArch64Template;
    }
    case llvm::Triple::riscv64: {
        return RISCVTemplate;
    }
    default:
        llvm::errs() << "Tried to get a template for an unsupported arch: "
                     << llvm::Triple::getArchTypeName(Arch) << " archNumber: " << Arch
                     << " this should not happen\n";
        exit(EXIT_FAILURE);
    }
}

} // namespace winic
