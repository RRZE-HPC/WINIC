#include "ErrorCode.h"

#include <string>

std::string ecToString(ErrorCode EC) {
    switch (EC) {
    case SUCCESS:
        return "SUCCESS";
    case NO_ERROR_CODE:
        return "NO_ERROR_CODE";
    case W_MULTIPLE_DEPENDENCIES:
        return "WARNING_MULTIPLE_DEPENDENCIES";
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
    case S_MANUALLY:
        return "SKIP_MANUALLY";
    case S_NO_MNEMONIC:
        return "SKIP_NO_MNEMONIC";
    case E_TEMPLATE:
        return "ERROR_TEMPLATE";
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
    case E_UNUSUAL_LATENCY:
        return "ERROR_UNUSUAL_LATENCY";
    case E_GENERIC:
        return "ERROR_GENERIC";
    }
    return "UNREACHABLE";
}

bool isError(ErrorCode EC) {
    return EC != SUCCESS && EC != W_MULTIPLE_DEPENDENCIES && EC != NO_ERROR_CODE;
}
