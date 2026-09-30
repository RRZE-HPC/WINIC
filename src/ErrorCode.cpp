#include "ErrorCode.h"

#include <Globals.h>
#include <string>
#include <vector>

namespace winic {

std::string ecToString(ErrorCode EC) {
    switch (EC) {
    case SUCCESS:
        return "SUCCESS";
    case NO_ERROR_CODE:
        return "NO_ERROR_CODE";
    case W_MULTIPLE_DEPENDENCIES:
        return "WARNING_MULTIPLE_DEPENDENCIES";
    case W_FLAGS_TO_FLAGS:
        return "WARNING_FLAGS_TO_FLAGS";
    case S_MEMORY_OPERAND:
        return "SKIP_MEMORY_OPERAND";
    case S_PCREL_OPERAND:
        return "SKIP_PCREL_OPERAND";
    case S_UNKNOWN_OPERAND:
        return "SKIP_UNKNOWN_OPERAND";
    case S_PSEUDO_INSTRUCTION:
        return "SKIP_PSEUDO_INSTRUCTION";
    case S_INSTRUCION_PREFIX:
        return "SKIP_INSTRUCION_PREFIX";
    case S_MAY_LOAD:
        return "SKIP_MAY_LOAD";
    case S_MAY_STORE:
        return "SKIP_MAY_STORE";
    case S_NON_MEMORY:
        return "SKIP_NON_MEMORY";
    case S_IS_CALL:
        return "SKIP_IS_CALL";
    case S_IS_META_INSTRUCTION:
        return "SKIP_IS_META_INSTRUCTION";
    case S_IS_RETURN:
        return "SKIP_IS_RETURN";
    case S_IS_BRANCH:
        return "SKIP_IS_BRANCH";
    case S_IS_CODE_GEN_ONLY:
        return "SKIP_IS_CODE_GEN_ONLY";
    case S_IS_X87FP:
        return "SKIP_IS_X87FP";
    case S_IS_NON_X87FP:
        return "S_IS_NON_X87FP";
    case S_MANUALLY:
        return "SKIP_MANUALLY";
    case S_NO_MNEMONIC:
        return "SKIP_NO_MNEMONIC";
    case S_BLACKLISTED_REGISTER:
        return "SKIP_BLACKLISTED_REGISTER";
    case S_RUNTIME_LIMIT:
        return "S_RUNTIME_LIMIT";
    case E_TEMPLATE:
        return "ERROR_TEMPLATE";
    case E_NO_RUNS:
        return "ERROR_NO_RUNS";
    case E_NO_HELPER:
        return "ERROR_NO_HELPER";
    case E_ASSEMBLY:
        return "ERROR_ASSEMBLY";
    case E_MMAP:
        return "ERROR_MMAP";
    case E_FORK:
        return "ERROR_FORK";
    case E_SIGSEGV:
        return "ERROR_SIGSEGV";
    case E_SIGNAL:
        return "ERROR_SIGNAL";
    case E_ILLEGAL_INSTRUCTION:
        return "ERROR_ILLEGAL_INSTRUCTION";
    case E_CPU_DETECT:
        return "ERROR_CPU_DETECT";
    case E_FILE:
        return "ERROR_FILE";
    case E_UNREACHABLE:
        return "ERROR_UNREACHABLE";
    case E_NO_REGISTERS:
        return "ERROR_NO_REGISTERS";
    case E_UNSUPPORTED_ARCH:
        return "ERROR_UNSUPPORTED_ARCH";
    case E_EXEC:
        return "ERROR_EXEC";
    case E_UNROLL_ANOMALY:
        return "ERROR_UNROLL_ANOMALY";
    case E_INVALID_REG_CLASS:
        return "ERROR_INVALID_REG_CLASS";
    case E_UNUSUAL_LATENCY:
        return "ERROR_UNUSUAL_LATENCY";
    case E_GENERIC:
        return "ERROR_GENERIC";
    }
    return "unknown error code";
}

bool isError(ErrorCode EC) {
    std::vector<ErrorCode> codes = {SUCCESS, W_MULTIPLE_DEPENDENCIES, W_FLAGS_TO_FLAGS,
                                    NO_ERROR_CODE, S_RUNTIME_LIMIT};
    return !contains(codes, EC);
}

bool finishedExecution(ErrorCode EC) {
    std::vector<ErrorCode> codes = {SUCCESS,           E_UNROLL_ANOMALY,
                                    E_UNUSUAL_LATENCY, W_MULTIPLE_DEPENDENCIES,
                                    W_FLAGS_TO_FLAGS,  NO_ERROR_CODE};
    return contains(codes, EC);
}

bool invalidatesOpcode(ErrorCode EC) {
    std::vector<ErrorCode> codes = {E_SIGNAL, E_EXEC, E_SIGSEGV, E_ILLEGAL_INSTRUCTION, E_ASSEMBLY};
    return contains(codes, EC);
}

bool hasResultWith(ErrorCode EC) {
    std::vector<ErrorCode> codes = {SUCCESS, W_MULTIPLE_DEPENDENCIES, NO_ERROR_CODE};
    return contains(codes, EC);
}

} // namespace winic
