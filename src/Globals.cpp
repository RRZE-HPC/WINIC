#include "Globals.h"

#include "LLVMDebug.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "llvm/TargetParser/Triple.h"
#include <iostream>

namespace winic {

LLVMEnvironment &getEnv() {
    static LLVMEnvironment env;
    return env;
}

std::unique_ptr<std::ofstream> fileStream;
std::ostream *ios = &std::cout;
bool includeX87FP;
bool includeNonX87FP;
bool includeMemory;
bool includeNonMemory;
bool keepEmptyEntries;

void setOutputToFile(const std::string &Filename) {
    fileStream = std::make_unique<std::ofstream>(Filename);
    if (fileStream->is_open()) {
        ios = fileStream.get(); // Redirect global output
    } else {
        std::cerr << "Failed to open file: " << Filename << std::endl;
        ios = &std::cout; // Fallback
    }
}

InstructionForm::InstructionForm(unsigned Opcode) : opcode(Opcode), operands({}) {
    const MCInstrDesc &desc = getEnv().MCII->get(Opcode);
    auto operandInfos = desc.operands();
    auto implDefs = desc.implicit_defs();
    auto implUses = desc.implicit_uses();
    std::vector<unsigned> aarch64MemBaseIndices;
    std::vector<unsigned> aarch64MemOffsetIndices;
    std::vector<unsigned> aarch64MemOpIndices;

    if (getEnv().Arch == llvm::Triple::aarch64) {
        unsigned aarch64MemBase = getEnv().getAArch64BaseOperandIndex(Opcode);
        unsigned aarch64MemOffset = getEnv().getAArch64OffsetOperandIndex(Opcode);
        unsigned tiedToMemBase = aarch64MemBase != NO_OP_INDEX
                                     ? getEnv().getTiedToOperand(desc.operands()[aarch64MemBase])
                                     : NO_OP_INDEX;
        unsigned tiedToMemOffset =
            aarch64MemOffset != NO_OP_INDEX
                ? getEnv().getTiedToOperand(desc.operands()[aarch64MemOffset])
                : NO_OP_INDEX;

        if (aarch64MemBase != NO_OP_INDEX) aarch64MemBaseIndices.emplace_back(aarch64MemBase);
        if (tiedToMemBase != NO_OP_INDEX) aarch64MemBaseIndices.emplace_back(tiedToMemBase);
        if (aarch64MemOffset != NO_OP_INDEX) aarch64MemOffsetIndices.emplace_back(aarch64MemOffset);
        if (tiedToMemOffset != NO_OP_INDEX) aarch64MemOffsetIndices.emplace_back(tiedToMemOffset);

        aarch64MemOpIndices = aarch64MemBaseIndices;
        aarch64MemOpIndices.insert(aarch64MemOpIndices.end(), aarch64MemOffsetIndices.begin(),
                                   aarch64MemOffsetIndices.end());
        dbg(__func__, desc);
        dbg(__func__, aarch64MemBase, " ", aarch64MemOffset);
    }

    unsigned currentIndex = 0;
    std::set<unsigned> processedOperands;
    // defs
    for (unsigned i = 0; i < desc.getNumDefs(); i++) {
        if (processedOperands.find(i) != processedOperands.end()) continue;
        processedOperands.insert(i);
        auto operandInfo = operandInfos[i];
        // check if this is an Aarch64 memory operand
        if (getEnv().Arch == llvm::Triple::aarch64 && (contains(aarch64MemOpIndices, i))) {
            processedOperands.insert(aarch64MemOpIndices.begin(), aarch64MemOpIndices.end());
            operands.emplace_back(
                OperandForm(currentIndex, aarch64MemOpIndices,
                            AArch64MemoryOperand(aarch64MemBaseIndices, aarch64MemOffsetIndices),
                            desc.mayStore(), desc.mayLoad()));
        } else if (operandInfo.OperandType == MCOI::OPERAND_REGISTER) {
            // check if there is a tiedTo use operand
            unsigned useIndex = NO_OP_INDEX;
            for (unsigned j = desc.getNumDefs(); j < operandInfos.size(); j++) {
                if ((getEnv().getTiedToOperand(operandInfos[j])) == i) {
                    useIndex = j;
                    processedOperands.insert(j);
                    break;
                }
            }
            auto incices = useIndex != NO_OP_INDEX ? std::vector<unsigned>{i, useIndex}
                                                   : std::vector<unsigned>{i};
            operands.emplace_back(OperandForm(currentIndex, incices,
                                              RegisterClassOperand(operandInfo.RegClass), true,
                                              useIndex != NO_OP_INDEX));
        } else if (operandInfo.OperandType == MCOI::OPERAND_MEMORY) {
            // x86 memory operand, collect all operands that make up this memory operand
            std::vector<unsigned> indices;
            for (int j = 0; j < 5; j++) {
                if (operandInfos[i + j].OperandType != MCOI::OPERAND_MEMORY)
                    return; // TODO how to handle
                indices.emplace_back(i + j);
                processedOperands.insert(i + j);
            }
            operands.emplace_back(OperandForm(
                currentIndex, indices, X86MemoryOperand({i}, {i + 1}, {i + 2}, {i + 3}, {i + 4}),
                desc.mayStore(), desc.mayLoad()));
            i = i + 4;
        } else if (operandInfo.OperandType == MCOI::OPERAND_IMMEDIATE) {
            // this should not happen, an immediate can not be a def
            std::cerr << "Unreachable: encountered an immediate operand written to." << std::endl;
            exit(1);
        } else
            continue;
        currentIndex++;
    }
    // uses
    for (unsigned i = desc.getNumDefs(); i < operandInfos.size(); i++) {
        if (processedOperands.find(i) != processedOperands.end()) continue;
        MCOperandInfo operandInfo = operandInfos[i];

        // check if this is an Aarch64 memory operand
        if (getEnv().Arch == llvm::Triple::aarch64 && (contains(aarch64MemOpIndices, i))) {
            processedOperands.insert(aarch64MemOpIndices.begin(), aarch64MemOpIndices.end());
            operands.emplace_back(
                OperandForm(currentIndex, aarch64MemOpIndices,
                            AArch64MemoryOperand(aarch64MemBaseIndices, aarch64MemOffsetIndices),
                            desc.mayStore(), desc.mayLoad()));
        } else if (operandInfo.OperandType == MCOI::OPERAND_REGISTER)
            operands.emplace_back(OperandForm(currentIndex, std::vector<unsigned>{i},
                                              RegisterClassOperand(operandInfo.RegClass), false,
                                              true));
        else if (operandInfo.OperandType == MCOI::OPERAND_MEMORY) {
            // x86 memory operand, collect all operands that make up this memory operand
            std::vector<unsigned> indices;
            for (int j = 0; j < 5; j++) {
                if (operandInfos[i + j].OperandType != MCOI::OPERAND_MEMORY)
                    return; // TODO how to handle
                indices.emplace_back(i + j);
                processedOperands.insert(i + j);
            }
            operands.emplace_back(OperandForm(
                currentIndex, indices, X86MemoryOperand({i}, {i + 1}, {i + 2}, {i + 3}, {i + 4}),
                desc.mayStore(), desc.mayLoad()));
            i = i + 4;
        } else if (operandInfo.OperandType == MCOI::OPERAND_IMMEDIATE) {
            operands.emplace_back(OperandForm(currentIndex, {i}, ImmediateOperand(), false, true));
        } else {
            // especially on aarch64 some types of immediates had operand type
            // UNKNOWN_OPERAND (idk why) speculatively plug in immediates and hope for the best
            // in llvm-20.1.5->22.1.8 the number of those instructions were reduced, see DEV.md
            // still, on some instructions, we need to generate an operand for successful
            // instruction printing
            operands.emplace_back(OperandForm(currentIndex, {i}, ImmediateOperand(), false, true));
        }
        currentIndex++;
    }
    // implicit defs
    for (unsigned i = 0; i < implDefs.size(); i++) {
        MCRegister defReg = implDefs[i];
        bool isUse = std::find(implUses.begin(), implUses.end(), defReg) != implUses.end();
        operands.emplace_back(
            OperandForm(currentIndex++, {}, RegisterOperand(defReg), true, isUse));
    }
    // implicit uses
    for (unsigned i = 0; i < implUses.size(); i++) {
        MCRegister useReg = implUses[i];
        // check if this was already added
        if (std::find(implDefs.begin(), implDefs.end(), useReg) != implDefs.end()) continue;
        operands.emplace_back(
            OperandForm(currentIndex++, {}, RegisterOperand(useReg), false, true));
    }
}

} // namespace winic
