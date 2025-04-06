#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/ARMTargetParser.h"
#include "llvm/TargetParser/Triple.h"
#include <cstdlib>
#include <set>
#include <string>

struct Template {
    std::string prefix;
    std::string postInit;
    std::string preInit;
    std::string preLoop;
    std::string beginLoop;
    std::string midLoop;
    std::string endLoop;
    std::string postLoop;
    std::set<std::string> usedRegisters;

    Template(std::string prefix, std::string preInit, std::string postInit, std::string preLoop,
             std::string beginLoop, std::string endLoop, std::string postLoop,
             std::set<std::string> usedRegisters)
        : prefix(std::move(prefix)), preInit(std::move(preInit)), postInit(std::move(postInit)),
          preLoop(std::move(preLoop)), beginLoop(std::move(beginLoop)), endLoop(std::move(endLoop)),
          postLoop(std::move(postLoop)), usedRegisters(std::move(usedRegisters)) {
        // for readability of this file strings have a leading newline
        // this gets removed here
        trimLeadingNewline(this->preLoop);
        trimLeadingNewline(this->beginLoop);
        trimLeadingNewline(this->midLoop);
        trimLeadingNewline(this->endLoop);
        trimLeadingNewline(this->postLoop);
    }

  private:
    void trimLeadingNewline(std::string &str) {
        if (!str.empty() && str[0] == '\n') {
            str.erase(0, 1);
        }
    }
};

static Template X86Template = {
    R"(
#define N edi
#define i r8d

.intel_syntax noprefix
.text
)", R"(
.globl init
.type init, @function
.align 32
init:
)", R"(
    ret
.size init, .-init
)", R"(

.globl latency
.type latency, @function
.align 32
latency:
        push      rbp
        mov       rbp, rsp
        xor       i, i
        test      N, N

)", R"(
        jle       done
loop:
        inc       i
)", R"(
        cmp       i, N
        jl        loop
done:
)", R"(
        mov  rsp, rbp
        pop rbp
        ret
.size latency, .-latency
)", {"edi", "r8d", "rbp", "rsp"}};

static Template AArch64Template = {
    R"(
#define N x0

.text

)", R"(
.globl init
.type init, @function
.align 32
init:
)", R"(
    ret
.size init, .-init
)", R"(

.globl latency
.type latency, @function
.align 2
latency:
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
)", R"(
loop:
)", R"(
        subs      x4, x4, #1
        bne       loop
done:
)", R"(
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

.size latency, .-latency
)", {"x0", "x4"}};

static Template getTemplate(llvm::Triple::ArchType Arch) {
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
