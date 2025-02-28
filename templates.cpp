#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include <cstdlib>
#include <set>
#include <string>

// the template for benchmarks is split up into parts to insert the benchmark loop and
// initialisation code
// build should look like this with {} constructed by the benchmark generator:
// preLoop {generated_reg_init/save_reg} beginLoop {instructions} midLoop
// {optional_instructions} endLoop {generated_restore_regs} postLoop
class Template {
  public:
    std::string preLoop;
    std::string beginLoop;
    std::string midLoop;
    std::string endLoop;
    std::string postLoop;
    std::set<std::string> usedRegisters;
};

class X86Template : public Template {

  public:
    X86Template() {
        // for readability of this file strings have a leading newline
        // this gets removed here
        preLoop = preLoop.substr(1);
        beginLoop = beginLoop.substr(1);
        midLoop = midLoop.substr(1);
        endLoop = endLoop.substr(1);
        postLoop = postLoop.substr(1);
    }
    std::string preLoop = R"(
#define N edi
#define i r8d


.intel_syntax noprefix
.globl ninst
.data
ninst:
.long NINST
.text
.globl latency
.type latency, @function
.align 32
latency:
        push      rbp
        mov       rbp, rsp
        xor       i, i
        test      N, N
        
)";

    std::string beginLoop = R"(
        jle       done
loop:
        inc       i
)";
    std::string midLoop = R"(
        cmp       i, N
)";
    std::string endLoop = R"(
        jl        loop
done:
)";
    std::string postLoop = R"(
        mov  rsp, rbp
        pop rbp
        ret
.size latency, .-latency
)";
    std::set<std::string> usedRegisters = {"edi", "r8d", "rbp", "rsp"};
};

class AArch64Template : public Template {

  public:
    AArch64Template() {
        // for readability of this file strings have a leading newline
        // this gets removed here
        preLoop = preLoop.substr(1);
        beginLoop = beginLoop.substr(1);
        midLoop = midLoop.substr(1);
        endLoop = endLoop.substr(1);
        postLoop = postLoop.substr(1);
    }
    std::string preLoop = R"(
#define NINST 48
#define N x0

.globl ninst
.data
ninst:
.long NINST
.text
.globl latency
.type latency, @function
.align 2
latency:
        mov     x4, N
)";

    std::string beginLoop = R"(
loop:
)";
    std::string midLoop = R"(
        cmp       i, N
)";
    std::string endLoop = R"(
        subs      x4, x4, #1
        bne       loop
done:
)";
    std::string postLoop = R"(
        ret

.size latency, .-latency
)";
    std::set<std::string> usedRegisters = {"x0", "x4"};
};

static Template getTemplate(llvm::Triple::ArchType Arch) {
    switch (Arch) {
    case llvm::Triple::x86_64:
        return X86Template();
    case llvm::Triple::aarch64:
        return AArch64Template();
    default:
        llvm::errs() << "Tried to get a template for an unsupported arch, this should not happen\n";
        exit(EXIT_FAILURE);
    }
}