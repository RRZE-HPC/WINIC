#include "ErrorCode.h"
#include <string>

std::string ecToString(ErrorCode EC) {
    switch (EC) {
    case SUCCESS:
        return "SUCCESS";
    case MEMORY_OPERAND:
        return "MEMORY_OPERAND";
    case PCREL_OPERAND:
        return "PCREL_OPERAND";
    case UNKNOWN_OPERAND:
        return "UNKNOWN_OPERAND";
    case PSEUDO_INSTRUCTION:
        return "PSEUDO_INSTRUCTION";
    case INSTRUCION_PREFIX:
        return "INSTRUCION_PREFIX";
    case MAY_LOAD:
        return "MAY_LOAD";
    case MAY_STORE:
        return "MAY_STORE";
    case IS_CALL:
        return "IS_CALL";
    case IS_META_INSTRUCTION:
        return "IS_META_INSTRUCTION";
    case IS_RETURN:
        return "IS_RETURN";
    case IS_BRANCH:
        return "IS_BRANCH";
    case IS_CODE_GEN_ONLY:
        return "IS_CODE_GEN_ONLY";
    case SKIP_MANUALLY:
        return "SKIP_MANUALLY";
    case DOES_NOT_EMIT_INST:
        return "DOES_NOT_EMIT_INST";
    case ERROR_TEMPLATE:
        return "ERROR_TEMPLATE";
    case ERROR_NO_HELPER:
        return "ERROR_NO_HELPER";
    case ERROR_ASSEMBLY:
        return "ERROR_ASSEMBLY";
    case ERROR_MMAP:
        return "ERROR_MMAP";
    case ERROR_FORK:
        return "ERROR_FORK";
    case ERROR_SIGSEGV:
        return "ERROR_SIGSEGV";
    case ERROR_SIGNAL:
        return "ERROR_SIGNAL";
    case ERROR_TARGET_DETECT:
        return "ERROR_TARGET_DETECT";
    case ILLEGAL_INSTRUCTION:
        return "ILLEGAL_INSTRUCTION";
    case ERROR_CPU_DETECT:
        return "ERROR_CPU_DETECT";
    case ERROR_FILE:
        return "ERROR_FILE";
    case ERROR_UNREACHABLE:
        return "ERROR_UNREACHABLE";
    case ERROR_NO_REGISTERS:
        return "ERROR_NO_REGISTERS";
    case ERROR_GEN_REQUIREMENT:
        return "ERROR_GEN_REQUIREMENT";
    case ERROR_UNSUPPORTED_ARCH:
        return "ERROR_UNSUPPORTED_ARCH";
    case ERROR_SIGFPE:
        return "ERROR_SIGFPE";
    case ERROR_EXEC:
        return "ERROR_EXEC";
    case ERROR_GENERIC:
        return "ERROR_GENERIC";
    default:
        return "description missing for this error";
    }
}