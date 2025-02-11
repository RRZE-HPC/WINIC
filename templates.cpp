#include <set>

class x86Template {
    // the template for x86 benchmarks split up into parts to insert the benchmark loop and
    // initialisation code
    // build should look like this with {} constructed by the benchmark generator:
    // preLoop {generated_reg_init/save_reg} beginLoop {instructions} midLoop
    // {optional_instructions} endLoop {generated_restore_regs} postLoop
  public:
    x86Template() {
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