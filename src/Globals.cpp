#include "Globals.h"

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
    unsigned currentIndex = 0;
    std::set<unsigned> processedOperands;
    // defs
    for (unsigned i = 0; i < desc.getNumDefs(); i++) {
        processedOperands.insert(i);
        auto operandInfo = operandInfos[i];
        if (operandInfo.OperandType == MCOI::OPERAND_REGISTER) {
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
            std::vector<unsigned> indices = {i};
            while (i + 1 < desc.getNumOperands() &&
                   operandInfos[i + 1].OperandType == MCOI::OPERAND_MEMORY) {
                // collect all operands that make up this register operand TODO x86 only
                processedOperands.insert(i + 1);
                indices.emplace_back(i + 1);
                i++;
            }
            operands.emplace_back(OperandForm(currentIndex, indices, MemoryOperand(),
                                              desc.mayStore(), desc.mayLoad()));
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
        if (operandInfo.OperandType == MCOI::OPERAND_REGISTER)
            operands.emplace_back(OperandForm(currentIndex, std::vector<unsigned>{i},
                                              RegisterClassOperand(operandInfo.RegClass), false,
                                              true));
        else if (operandInfo.OperandType == MCOI::OPERAND_MEMORY) {
            std::vector<unsigned> indices = {i};
            while (i + 1 < desc.getNumOperands() &&
                   operandInfos[i + 1].OperandType == MCOI::OPERAND_MEMORY) {
                // collect all operands that make up this register operand TODO x86 only
                processedOperands.insert(i + 1);
                indices.emplace_back(i + 1);
                i++;
            }
            operands.emplace_back(OperandForm(currentIndex, indices, MemoryOperand(),
                                              desc.mayStore(), desc.mayLoad()));
        } else if (operandInfo.OperandType == MCOI::OPERAND_IMMEDIATE) {
            operands.emplace_back(OperandForm(currentIndex, {i}, ImmediateOperand(), false, true));
        } else {
            // especially on aarch64 some types of immediates had operand type
            // UNKNOWN_OPERAND (idk why) speculatively plug in immediates and hope for the best
            // in llvm-20.1.5->22.1.8 the number of those instructions were reduced, see DEV.md
            // still, on some instructions, we need to generate an operand for successful instruction
            // printing
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
