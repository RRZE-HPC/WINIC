#include "Globals.h"

#include "LLVMDebug.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "MCTargetDesc/RISCVBaseInfo.h"
#include "llvm/TargetParser/Triple.h"
#include <iostream>
#include <llvm/MC/MCInstrDesc.h>

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
    std::vector<unsigned> memBaseIndices;
    std::vector<unsigned> memOffsetIndices;
    std::vector<unsigned> memOpIndices;

    if (getEnv().isAArch64()) {
        // handle AArch64 memory operands beforehand as they are not marked as OPERAND_MEMORY
        unsigned memBase = getEnv().getAArch64BaseOperandIndex(Opcode);
        unsigned memOffset = getEnv().getAArch64OffsetOperandIndex(Opcode);
        unsigned tiedToMemBase =
            memBase != NO_OP_INDEX ? getEnv().getTiedToOperand(operandInfos[memBase]) : NO_OP_INDEX;
        unsigned tiedToMemOffset = memOffset != NO_OP_INDEX
                                       ? getEnv().getTiedToOperand(operandInfos[memOffset])
                                       : NO_OP_INDEX;

        if (memBase != NO_OP_INDEX) memBaseIndices.emplace_back(memBase);
        if (tiedToMemBase != NO_OP_INDEX) memBaseIndices.emplace_back(tiedToMemBase);
        if (memOffset != NO_OP_INDEX) memOffsetIndices.emplace_back(memOffset);
        if (tiedToMemOffset != NO_OP_INDEX) memOffsetIndices.emplace_back(tiedToMemOffset);

        memOpIndices = memBaseIndices;
        memOpIndices.insert(memOpIndices.end(), memOffsetIndices.begin(), memOffsetIndices.end());
    }

    unsigned currentIndex = 0;
    std::set<unsigned> processedOperands;
    // defs
    for (unsigned i = 0; i < desc.getNumOperands(); i++) {
        bool def = i < desc.getNumDefs();
        if (processedOperands.find(i) != processedOperands.end()) continue;
        processedOperands.insert(i);
        auto operandInfo = operandInfos[i];
        // check if this is an Aarch64 memory operand
        if (contains(memOpIndices, i)) {
            processedOperands.insert(memOpIndices.begin(), memOpIndices.end());
            auto memoryOperand =
                getEnv().isAArch64()
                    ? OperandKind{AArch64MemoryOperand(memBaseIndices, memOffsetIndices)}
                    : OperandKind{RISCVMemoryOperand(memBaseIndices, memOffsetIndices)};
            operands.emplace_back(OperandForm(currentIndex, memOpIndices, std::move(memoryOperand),
                                              desc.mayStore(), desc.mayLoad()));
        } else if (operandInfo.OperandType == MCOI::OPERAND_REGISTER) {
            if (def) {
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
            } else {
                operands.emplace_back(OperandForm(currentIndex, std::vector<unsigned>{i},
                                                  RegisterClassOperand(operandInfo.RegClass), false,
                                                  true));
            }
        } else if (operandInfo.OperandType == MCOI::OPERAND_MEMORY) {
            if (getEnv().isX86()) {
                // x86 memory operand, collect all operands that make up this memory operand
                std::vector<unsigned> indices;
                for (int j = 0; j < 5; j++) {
                    if (operandInfos.size() < i + j + 1 ||
                        operandInfos[i + j].OperandType != MCOI::OPERAND_MEMORY)
                        return; // TODO how to handle
                    indices.emplace_back(i + j);
                    processedOperands.insert(i + j);
                }
                operands.emplace_back(
                    OperandForm(currentIndex, indices,
                                X86MemoryOperand({i}, {i + 1}, {i + 2}, {i + 3}, {i + 4}),
                                desc.mayStore(), desc.mayLoad()));
                i = i + 4;
            }
            if (getEnv().isRISCV()) {
                // on RISCV there are mostly single OPERAND_MEMORYs or OPERAND_MEMORY followed by
                // some target specific immediate
                std::set<RISCVOp::OperandType> memImmTypes = {
                    RISCVOp::OperandType::OPERAND_UIMM2,
                    RISCVOp::OperandType::OPERAND_UIMM2_LSB0,
                    RISCVOp::OperandType::OPERAND_UIMM4,
                    RISCVOp::OperandType::OPERAND_UIMM5,
                    RISCVOp::OperandType::OPERAND_UIMM5_LSB0,
                    RISCVOp::OperandType::OPERAND_UIMM6_LSB0,
                    RISCVOp::OperandType::OPERAND_UIMM7_LSB00,
                    RISCVOp::OperandType::OPERAND_UIMM8_LSB00,
                    RISCVOp::OperandType::OPERAND_UIMM8_LSB000,
                    RISCVOp::OperandType::OPERAND_UIMM9_LSB000,
                    RISCVOp::OperandType::OPERAND_SIMM12_LSB00000,
                    RISCVOp::OperandType::OPERAND_SIMM26,
                    RISCVOp::OperandType::OPERAND_SIMM12_LO,
                    RISCVOp::OperandType::OPERAND_VMASK, // unsure if this works
                };
                std::vector<unsigned> mcIndices = {i};
                std::vector<unsigned> offsetIndices = {};
                if (i + 1 < operandInfos.size() &&
                    contains(memImmTypes, operandInfos[i + 1].OperandType)) {
                    mcIndices.emplace_back(i + 1);
                    offsetIndices.emplace_back(i + 1);
                }
                operands.emplace_back(OperandForm(currentIndex, mcIndices,
                                                  RISCVMemoryOperand({i}, offsetIndices),
                                                  desc.mayStore(), desc.mayLoad()));
                i += mcIndices.size();
            }
        } else if (operandInfo.OperandType == MCOI::OPERAND_IMMEDIATE) {
            // Immediates can only be uses
            operands.emplace_back(OperandForm(currentIndex, {i}, ImmediateOperand(), false, true));
        } else {
            // especially on aarch64 some types of immediates had operand type
            // UNKNOWN_OPERAND (idk why) speculatively plug in TargetSpecificOperand and hope for
            // the best in llvm-20.1.5->22.1.8 the number of those instructions were reduced, see
            // DEV.md still, on some instructions, we need to generate an operand for successful
            // instruction printing
            operands.emplace_back(OperandForm(
                currentIndex, {i}, TargetSpecificOperand(operandInfo.OperandType), def, !def));
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

bool InstructionForm::hasDefOfMemBaseRegister() const {
    for (OperandForm opForm : operands) {
        if (!opForm.isMemory()) continue;
        MemoryOperand memOp = opForm.getMemoryOperand();
        const MCInstrDesc &desc = getEnv().MCII->get(opcode);
        for (unsigned mcInd : memOp.baseIndices) {
            if (mcInd < desc.getNumDefs()) return true;
        }
    }
    return false;
}

bool OperandForm::hasMemoryOffsetImm() const {
    if (!isMemory()) return false;
    return !getMemoryOperand().offsetIndices.empty();
}

MCRegister OperandForm::getRegister() const {
    assert(isRegister());
    return std::get_if<RegisterOperand>(&kind)->getRegister();
}

bool OperandForm::hasValidRegClassId() const {
    assert(isRegClass());
    return std::get_if<RegisterClassOperand>(&kind)->hasValidRegClassId();
}

unsigned OperandForm::getRegClassID() const {
    assert(isRegClass());
    return std::get_if<RegisterClassOperand>(&kind)->getRegClassID();
}

void OperandForm::setRegClassOperand(MCInst *Inst, MCRegister Reg) {
    assert(isRegClass());
    initMCInst(Inst);
    for (auto mcInd : mcIndices) {
        Inst->getOperand(mcInd) = MCOperand::createReg(Reg);
    }
}

void OperandForm::setImmediateOperand(MCInst *Inst, unsigned Imm) {
    assert(isImmediate());
    initMCInst(Inst);
    for (auto mcInd : mcIndices) {
        Inst->getOperand(mcInd) = MCOperand::createImm(Imm);
    }
}

void OperandForm::setMemoryOperand(MCInst *Inst, MCRegister BaseRegister, unsigned Displacement) {
    assert(isMemory());
    initMCInst(Inst);
    MemoryOperand memOp = getMemoryOperand();
    for (unsigned index : memOp.baseIndices)
        Inst->getOperand(index) = MCOperand::createReg(BaseRegister);
    for (unsigned index : memOp.offsetIndices)
        Inst->getOperand(index) = MCOperand::createImm(Displacement);

    // only x86 has more than base and offset
    if (getEnv().isX86()) {
        X86MemoryOperand *memOp = std::get_if<X86MemoryOperand>(&kind);

        for (unsigned index : memOp->scaleIndices)
            Inst->getOperand(index) = MCOperand::createImm(0);
        for (unsigned index : memOp->indexIndices)
            Inst->getOperand(index) = MCOperand::createReg(0);
        for (unsigned index : memOp->segmentIndices)
            Inst->getOperand(index) = MCOperand::createReg(0);
    }
}

void OperandForm::setTargetSpecificOperand(MCInst *Inst, unsigned Imm) {
    assert(isTargetSpecific());
    initMCInst(Inst);
    // TODO for more consistent generation, we could handle all target specific operand types
    // e.g. like this:
    /*
    if (getEnv().isRISCV()) {
        // this map selects a value for each possible operand type to be used
        // allowed values are inferred from RISCVInstrInfo::verifyInstruction()
        std::map<unsigned, long> valueMap = {
            {RISCVOp::OPERAND_THREE, 3},
            {RISCVOp::OPERAND_FOUR, 4},
        };
        ...
    }
    */
    // however, i dont have time for this so for now we just attempt to plug in immediates
    for (auto mcInd : mcIndices)
        Inst->getOperand(mcInd) = MCOperand::createImm(Imm);
}

unsigned OperandForm::getMemoryOperandOffset(MCInst Inst) {
    assert(hasMemoryOffsetImm());
    MemoryOperand memOp = getMemoryOperand();
    return Inst.getOperand(memOp.offsetIndices[0]).getImm();
}

MCRegister OperandForm::getMemoryOperandBaseReg(MCInst *Inst) {
    MemoryOperand memOp = getMemoryOperand();
    return Inst->getOperand(memOp.baseIndices[0]).getReg();
}

} // namespace winic
