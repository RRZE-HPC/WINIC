#ifndef ERROR_CODE_H
#define ERROR_CODE_H

#include <string>

enum ErrorCode {
    SUCCESS,
    NO_ERROR_CODE,
    W_MULTIPLE_DEPENDENCIES, //warnings
    S_MEMORY_OPERAND, //skip reasons
    S_PCREL_OPERAND,
    S_UNKNOWN_OPERAND,
    S_PSEUDO_INSTRUCTION,
    S_INSTRUCION_PREFIX,
    S_MAY_LOAD,
    S_MAY_STORE,
    S_IS_CALL,
    S_IS_META_INSTRUCTION,
    S_IS_RETURN,
    S_IS_BRANCH,
    S_IS_CODE_GEN_ONLY,
    S_IS_X87FP,
    S_MANUALLY,
    S_NO_MNEMONIC,
    E_TEMPLATE, //errors
    E_NO_HELPER,
    E_ASSEMBLY,
    E_MMAP,
    E_FORK,
    E_SIGSEGV,
    E_CPU_DETECT,
    E_FILE,
    E_ILLEGAL_INSTRUCTION,
    E_SIGNAL,
    E_UNREACHABLE,
    E_NO_REGISTERS,
    E_UNSUPPORTED_ARCH,
    E_EXEC,
    E_UNROLL_ANOMALY,
    E_UNUSUAL_LATENCY,
    E_GENERIC,
};

std::string ecToString(ErrorCode EC);

// returns true if EC is SUCCESS, a warning or the default EC
bool isError(ErrorCode EC);

#endif // ERROR_CODE_H
