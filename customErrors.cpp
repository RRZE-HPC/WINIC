#include <string>

enum ErrorCode {
    SUCCESS,
    MEMORY_OPERAND,
    PCREL_OPERAND,
    UNKNOWN_OPERAND,
    PSEUDO_INSTRUCTION,
    INSTRUCION_PREFIX,
    MAY_LOAD,
    MAY_STORE,
    IS_CALL,
    IS_META_INSTRUCTION,
    IS_RETURN,
    IS_BRANCH,
    IS_CODE_GEN_ONLY,
    ERROR_TEMPLATE,
    ERROR_ASSEMBLY,
    ERROR_MMAP,
    ERROR_FORK,
    ERROR_SIGSEGV,
    ILLEGAL_INSTRUCTION,
    ERROR_GENERIC,
};

static std::string ecToString(ErrorCode EC) {
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
    case ERROR_TEMPLATE:
        return "ERROR_TEMPLATE";
    case ERROR_ASSEMBLY:
        return "ERROR_ASSEMBLY";
    case ERROR_MMAP:
        return "ERROR_MMAP";
    case ERROR_FORK:
        return "ERROR_FORK";
    case ERROR_SIGSEGV:
        return "ERROR_SIGSEGV";
    case ILLEGAL_INSTRUCTION:
        return "ILLEGAL_INSTRUCTION";
    case ERROR_GENERIC:
        return "ERROR_GENERIC";
    default:
        return "description missing for this error";
    }
}