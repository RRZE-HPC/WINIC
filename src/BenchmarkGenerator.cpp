#include "BenchmarkGenerator.h"

#include "AssemblyFile.h"
#include "CustomDebug.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "LLVMDebug.h"
#include "LLVMEnvironment.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "Templates.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace winic {

std::vector<LatMeasurement> genLatMeasurements(unsigned Opcode) {
    // generate a LatMeasurement for each read write dependency combination possible
    // assumes there are no implicit memory defs TODO think
    // llvm x86 memory operands are split into 5 regs/immediates, but are not indicated to be
    // written to by MCInstDesc::NumDefs

    std::vector<LatMeasurement> measurements;
    ErrorCode ec = isValid(Opcode);
    if (ec != SUCCESS) {
        dbg(__func__, getEnv().MCII->getName(Opcode), " skipped for reason ", ecToString(ec));
        return {};
    }

    // build measurements
    InstructionForm instruction = InstructionForm(Opcode);
    for (auto defOp : instruction.getDefOps()) {
        for (auto useOp : instruction.getUseOps()) {
            LatMeasurement m =
                LatMeasurement(Opcode, DependencyType(defOp.getKind(), useOp.getKind()),
                               defOp.getIndex(), useOp.getIndex());
            measurements.emplace_back(m);
        }
    }
    return measurements;
}

std::pair<ErrorCode, AssemblyFile>
genLatBenchmark(const std::vector<LatMeasurement> &Measurements, unsigned *TargetInstrCount,
                std::set<MCRegister> UsedRegisters, long RegInitValue, long Immediate) {
    dbg(__func__, "Measurements.size(): ", Measurements.size(),
        " TargetInstrCount: ", *TargetInstrCount, " UsedRegisters.size(): ", UsedRegisters.size());
    auto benchTemplate = getTemplate();
    // extract list of registers used by the template
    for (unsigned i = 0; i < getEnv().MRI->getNumRegs(); i++) {
        MCRegister reg = MCRegister::from(i);
        if (benchTemplate.usedRegisters.find(getEnv().TRI->getRegAsmName(reg).lower().data()) !=
            benchTemplate.usedRegisters.end())
            UsedRegisters.insert(reg);
    }

    // generate an instruction for every measurement. When e.g. two instructions are interleaved to
    // form a latency chain, Measurements.size is 2
    std::map<unsigned, MCRegister> chosenRegisters;
    std::vector<MCInst> instructions;
    for (unsigned i = 0; i < Measurements.size(); i++) {
        LatMeasurement m = Measurements.at(i);
        unsigned memDisplacement = i * getEnv().getMemoryOperandWidthUpperBound(m.opcode);
        std::map<unsigned, MCRegister> constraints;

        // choose registers for the operands building the latency chain
        for (auto [opIndex, op] :
             {std::make_pair(m.defIndex, m.type.defOp), std::make_pair(m.useIndex, m.type.useOp)}) {
            if (auto *registerClassOperand = std::get_if<RegisterClassOperand>(&op)) {
                // currently only the class is known, we have to specify which register to
                // use for generating the instruction
                unsigned regClassID = registerClassOperand->getRegClassID();
                if (chosenRegisters.find(regClassID) != chosenRegisters.end()) {
                    // we already chose a register for this class
                    constraints.insert({opIndex, chosenRegisters[regClassID]});
                } else {
                    // no register chosen for this class yet, choose a register
                    // from the class to use in all instructions
                    auto [EC, chosenReg] = getFreeRegisterInClass(regClassID, UsedRegisters);
                    if (isError(EC)) return {EC, AssemblyFile()};
                    constraints.insert({opIndex, chosenReg});
                    chosenRegisters.insert({regClassID, chosenReg});
                    UsedRegisters.insert(chosenReg);
                }
            } else if (auto *registerOperand = std::get_if<RegisterOperand>(&op))
                // implicit def/use -> this provides a register directly
                UsedRegisters.insert(registerOperand->getRegister());
            else if (std::holds_alternative<AArch64MemoryOperand>(op) ||
                     std::holds_alternative<X86MemoryOperand>(op) ||
                     std::holds_alternative<RISCVMemoryOperand>(op)) {
                memDisplacement = 0;
            }
        }

        auto [EC, instruction] =
            genInst(m.opcode, constraints, UsedRegisters, Immediate, memDisplacement);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        instructions.emplace_back(instruction);
    }

    // save registers used
    std::string saveRegs;
    std::string restoreRegs;
    for (MCRegister reg : UsedRegisters) {
        if (getEnv().TRI->isCalleeSavedPhysReg(reg, *getEnv().MF)) {
            // generate code to save and restore register
            // this currently also saves registers already saved in the template
            // which is redundant but not harmful
            auto [EC1, save] = genSaveRegister(reg);
            if (EC1 != SUCCESS) return {EC1, AssemblyFile()};
            saveRegs.append(save);
            auto [EC2, restore] = genRestoreRegister(reg);
            if (EC2 != SUCCESS) return {EC2, AssemblyFile()};
            restoreRegs.insert(0, restore);
        }
    }

    // if this benchmark accesses memory, set the memory base register to the buffer address each
    // iteration so loads/stores with auto-increment don't segfault
    std::string setMemCode = "";
    for (auto m : Measurements)
        if (getEnv().mayAccessMemory(m.opcode))
            setMemCode = str(benchTemplate.setScratchMemoryBaseReg, "\n");

    std::string loopCode;
    llvm::raw_string_ostream lco(loopCode);
    for (unsigned i = 0; i < *TargetInstrCount; ++i) {
        for (auto inst : instructions) {
            getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, lco);
            lco << "\n";
        }
    }
    std::string initCode;
    std::string regInit;
    llvm::raw_string_ostream ico(initCode);
    llvm::raw_string_ostream rio(regInit);
    ico << saveRegs << "\n";
    rio << genRegInitCode(instructions, RegInitValue);
    for (auto inst : instructions) {
        // execute each instruction once in the init function to e.g. mark registers as avx
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, ico);
        ico << "\n";
    }
    ico << restoreRegs << "\n";

    AssemblyFile assemblyFile;
    assemblyFile.addInitFunction("init", initCode);
    assemblyFile.addBenchFunction("lat", saveRegs + regInit, setMemCode + loopCode, restoreRegs,
                                  "init", *TargetInstrCount * instructions.size());
    assemblyFile.addBenchFunction("lat2", saveRegs + regInit, setMemCode + loopCode + loopCode,
                                  restoreRegs, "init", *TargetInstrCount * instructions.size() * 2);

    // check if each instruction of the sequence has exactly one dependency to the next one.
    // otherwise return a warning
    for (size_t i = 0; i < instructions.size() - 1; i++)
        if (getDependencies(instructions[i], instructions[i + 1]).size() != 1)
            return {W_MULTIPLE_DEPENDENCIES, assemblyFile};

    if (getDependencies(instructions[instructions.size() - 1], instructions[0]).size() != 1)
        return {W_MULTIPLE_DEPENDENCIES, assemblyFile};

    return {SUCCESS, assemblyFile};
}

std::pair<ErrorCode, AssemblyFile>
genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount, unsigned UnrollCount,
               std::set<MCRegister> UsedRegisters, std::map<unsigned, MCRegister> HelperConstraints,
               unsigned HelperOpcode, long RegInitValue, long Immediate) {
    dbg(__func__, "Opcode: ", Opcode, " Name: ", getEnv().MCII->getName(Opcode).str(),
        " TargetInstrCount: ", *TargetInstrCount, " UnrollCount: ", UnrollCount,
        " UsedRegisters.size(): ", UsedRegisters.size(),
        " HelperConstraints.size(): ", HelperConstraints.size());
    if (HelperOpcode != MAX_UNSIGNED)
        dbg(__func__, "Helper: ", getEnv().MCII->getName(HelperOpcode));
    auto benchTemplate = getTemplate();
    // extract list of registers used by the template
    // TODO optimize
    for (unsigned i = 0; i < getEnv().MRI->getNumRegs(); i++) {
        MCRegister reg = MCRegister::from(i);
        if (benchTemplate.usedRegisters.find(getEnv().TRI->getRegAsmName(reg).lower().data()) !=
            benchTemplate.usedRegisters.end()) {
            UsedRegisters.insert(reg);
        }
    }

    // this is the helper instruction if needed.
    std::vector<unsigned> opcodes = {Opcode};
    if (HelperOpcode != MAX_UNSIGNED) opcodes.emplace_back(HelperOpcode);
    auto [EC, instructions] =
        genTPLoop(opcodes, {{}, HelperConstraints}, *TargetInstrCount, UsedRegisters, Immediate);
    if (EC != SUCCESS) return {EC, AssemblyFile()};

    // update TargetInstructionCount to actual number of instructions generated, not
    // including helper instructions
    *TargetInstrCount = UnrollCount * instructions.size();
    if (HelperOpcode != MAX_UNSIGNED) *TargetInstrCount = *TargetInstrCount / 2;

    // save registers used (genTPInnerLoop updates usedRegisters)
    std::string saveRegs;
    std::string restoreRegs;
    for (MCRegister reg : UsedRegisters) {
        if (getEnv().TRI->isCalleeSavedPhysReg(reg, *getEnv().MF)) {
            // generate code to save and restore register
            // this currently also saves registers already saved in the template
            // which is redundant but not harmful
            auto [EC1, save] = genSaveRegister(reg);
            if (EC1 != SUCCESS) return {EC1, AssemblyFile()};
            saveRegs.append(save);
            auto [EC2, restore] = genRestoreRegister(reg);
            if (EC2 != SUCCESS) return {EC2, AssemblyFile()};
            restoreRegs.insert(0, restore);
        }
    }

    std::string regInit = genRegInitCode(instructions, RegInitValue);
    std::string singleLoopCode;
    llvm::raw_string_ostream slo(singleLoopCode);
    // build loop code
    for (auto inst : instructions) {
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, slo);
        slo << "\n";
    }

    // if this benchmark accesses memory, set the memory base register to the buffer address each
    // iteration so loads/stores with auto-increment don't segfault
    std::string setMemCode = "";
    if (getEnv().mayAccessMemory(Opcode) ||
        (HelperOpcode != MAX_UNSIGNED && getEnv().mayAccessMemory(HelperOpcode)))
        setMemCode = str(benchTemplate.setScratchMemoryBaseReg, "\n");

    std::string loopCode;
    for (unsigned i = 0; i < UnrollCount; i++)
        loopCode.append(singleLoopCode);

    std::string initCode = saveRegs + singleLoopCode + restoreRegs + "\n";

    AssemblyFile assemblyFile;
    assemblyFile.addInitFunction("init", initCode);
    assemblyFile.addBenchFunction("tp", saveRegs + regInit, setMemCode + loopCode, restoreRegs,
                                  "init", instructions.size());
    assemblyFile.addBenchFunction("tp2", saveRegs + regInit, setMemCode + loopCode + loopCode,
                                  restoreRegs, "init", instructions.size() * 2);
    return {SUCCESS, assemblyFile};
}

std::pair<ErrorCode, std::vector<MCInst>>
genTPLoop(std::vector<unsigned> Opcodes,
          std::vector<std::map<unsigned, MCRegister>> ConstraintsVector, unsigned TargetInstrCount,
          std::set<MCRegister> &UsedRegisters, long Immediate) {
    std::vector<MCInst> instructions;
    for (unsigned i = 0; i < Opcodes.size(); i++) {
        unsigned opcode = Opcodes[i];
        // this is the first generated instruction, all other instructions will use the
        // same registers as this one if they are only read
        unsigned memSize = getEnv().getMemoryOperandWidthUpperBound(opcode);
        unsigned memOffset = getEnv().hasWriteOnMemRegister(opcode) ? memSize : 0;
        auto [EC, refInst] =
            genInst(opcode, ConstraintsVector[i], UsedRegisters, Immediate, memOffset);
        if (EC != SUCCESS) return {EC, instructions};
        instructions.push_back(refInst);

        // constrain all other instructions of this opcode to use the same use registers as the
        // first one
        InstructionForm instructionForm = InstructionForm(opcode);
        for (auto operand : instructionForm.getUseOnlyOps()) {
            if (operand.isRegClass())
                ConstraintsVector[i].insert({operand.getIndex(), operand.getReg(&refInst)});
        }
    }

    for (unsigned i = 1; i < TargetInstrCount; ++i) {
        // only insert complete sets of instructions into the final list. (Registers may run out
        // mid generation)
        std::list<MCInst> tempInstructions;
        for (unsigned j = 0; j < Opcodes.size(); j++) {
            unsigned memSize = getEnv().getMemoryOperandWidthUpperBound(Opcodes[j]);
            // normally we use a different offset for each instruction to avoid dependencies. If
            // this instruction increments its base register, we should not do that as the scratch
            // memory will not be large enough
            unsigned memOffset = getEnv().hasWriteOnMemRegister(Opcodes[j]) ? memSize : i * memSize;

            auto [EC, inst] =
                genInst(Opcodes[j], ConstraintsVector[j], UsedRegisters, Immediate, memOffset);
            if (EC == E_NO_REGISTERS) return {SUCCESS, instructions}; // shorter loops are ok
            if (EC != SUCCESS) return {EC, {instructions}};
            tempInstructions.push_back(inst);
        }
        instructions.insert(instructions.end(), tempInstructions.begin(), tempInstructions.end());
    }
    return {SUCCESS, instructions};
}

std::tuple<ErrorCode, int>
whichOperandCanUse(unsigned Opcode, std::string Type, MCRegister RequiredRegister) {
    const MCInstrDesc &desc = getEnv().MCII->get(Opcode);
    if (Type == "use") {
        if (desc.hasImplicitUseOfPhysReg(RequiredRegister)) return {SUCCESS, -1};
        for (unsigned i = desc.getNumDefs(); i < desc.getNumOperands(); i++)
            if (desc.operands()[i].OperandType == MCOI::OPERAND_REGISTER)
                if (getEnv().regInRegClass(RequiredRegister, desc.operands()[i].RegClass))
                    return {SUCCESS, i};
    } else if (Type == "def") {
        if (desc.hasImplicitDefOfPhysReg(RequiredRegister)) {
            return {SUCCESS, -1};
        }
        for (unsigned i = 0; i < desc.getNumDefs(); i++)
            if (desc.operands()[i].OperandType == MCOI::OPERAND_REGISTER)
                if (getEnv().regInRegClass(RequiredRegister, desc.operands()[i].RegClass))
                    return {SUCCESS, i};
    } else {
        std::cerr << "choose between use and def" << std::endl;
        return {E_UNREACHABLE, 0};
    }
    return {E_GENERIC, 0};
}

std::pair<ErrorCode, MCInst>
genInst(unsigned Opcode, std::map<unsigned, MCRegister> Constraints,
        std::set<MCRegister> &UsedRegisters, unsigned Immediate, unsigned MemDisplacement) {

    // make sure fixed registers are not used anywhere else than they are supposed to by adding
    // them to usedRegisters beforehand
    std::set<MCRegister> localUsedRegisters;
    for (auto c : Constraints)
        localUsedRegisters.insert(c.second);

    MCInst inst;
    inst.setOpcode(Opcode);
    inst.clear();
    InstructionForm instructionForm = InstructionForm(Opcode);
    for (auto op : instructionForm.getOperands()) {
        // check for constraint
        if (Constraints.find(op.getIndex()) != Constraints.end()) {
            op.setRegClassOperand(&inst, Constraints[op.getIndex()]);
            continue;
        }
        if (op.isMemory()) {
            op.setMemoryOperand(&inst, getTemplate().scratchMemoryBaseReg, MemDisplacement);
        }
        if (op.isImmediate()) {
            op.setImmediateOperand(&inst, Immediate);
        }
        if (op.isTargetSpecific()) {
            op.setTargetSpecificOperand(&inst, Immediate);
        }
        if (op.isRegClass()) {
            bool foundRegister = false;
            const MCRegisterClass &regClass = getEnv().MRI->getRegClass(op.getRegClassID());
            for (MCRegister reg : regClass) {
                if ((getEnv().isX86() && reg.id() == X86::RIP) || reg.id() >= getEnv().MaxReg)
                    // RIP register (58) is included in GR64 class which is a bug as of
                    // LLVM 22.1.8 see X86RegisterInfo.td:586
                    continue;
                // don't use this if sub- or superregisters are in usedRegisters
                if (std::any_of(UsedRegisters.begin(), UsedRegisters.end(),
                                [reg](MCRegister R) { return getEnv().TRI->regsOverlap(reg, R); }))
                    continue;

                // don't reuse any registers
                if (std::any_of(localUsedRegisters.begin(), localUsedRegisters.end(),
                                [reg](MCRegister R) { return getEnv().TRI->regsOverlap(reg, R); }))
                    continue;

                op.setRegClassOperand(&inst, reg);
                localUsedRegisters.insert(reg);
                foundRegister = true;
                break;
            }
            if (!foundRegister) return {E_NO_REGISTERS, {}};
        }
    }

    UsedRegisters.insert(localUsedRegisters.begin(), localUsedRegisters.end());
    return {SUCCESS, inst};
}

std::pair<ErrorCode, MCRegister> getSupermostRegister(MCRegister Reg) {
    for (unsigned i = 0; i < 100; i++) {
        if (getEnv().TRI->superregs(Reg).empty()) return {SUCCESS, Reg};
        Reg = *getEnv().TRI->superregs(Reg).begin(); // take first superreg
    }
    std::cerr << "cannot get supermost register" << std::endl;
    return {E_UNREACHABLE, NULL};
}

std::pair<ErrorCode, MCRegister>
getFreeRegisterInClass(const MCRegisterClass &RegClass, std::set<MCRegister> UsedRegisters) {
    for (auto reg : RegClass)
        for (auto usedReg : UsedRegisters) {
            if (!getEnv().TRI->regsOverlap(reg, usedReg)) {
                return {SUCCESS, reg};
            }
        }
    return {E_NO_REGISTERS, MAX_UNSIGNED};
}

std::pair<ErrorCode, MCRegister>
getFreeRegisterInClass(unsigned RegClassID, std::set<MCRegister> UsedRegisters) {
    const MCRegisterClass &regClass = getEnv().MRI->getRegClass(RegClassID);
    return getFreeRegisterInClass(regClass, UsedRegisters);
}

std::list<DependencyType> getDependencies(MCInst Inst1, MCInst Inst2) {
    std::list<DependencyType> dependencies;
    InstructionForm instructionForm1 = InstructionForm(Inst1.getOpcode());
    InstructionForm instructionForm2 = InstructionForm(Inst2.getOpcode());

    // collect all registers and memory locations Inst1 will define
    std::set<MCRegister> defs1;
    std::set<int64_t> memOffsets1;
    for (OperandForm operandForm : instructionForm1.getDefOps()) {
        if (operandForm.isRegister()) defs1.insert(operandForm.getRegister());
        if (operandForm.isRegClass())
            defs1.insert(Inst1.getOperand(operandForm.getMCIndices()[0]).getReg());
        if (operandForm.isMemory()) memOffsets1.insert(operandForm.getMemoryOperandOffset(Inst1));
    }

    // collect all registers and memory locations Inst2 will use
    std::set<MCRegister> uses2;
    std::set<int64_t> memOffsets2;
    for (OperandForm operandForm : instructionForm2.getUseOps()) {
        if (operandForm.isRegister()) uses2.insert(operandForm.getRegister());
        if (operandForm.isRegClass())
            uses2.insert(Inst2.getOperand(operandForm.getMCIndices()[0]).getReg());
        if (operandForm.isMemory()) memOffsets2.insert(operandForm.getMemoryOperandOffset(Inst2));
    }

    // create dependencyType for every register which is defined by 1 and used by 2
    for (MCRegister def : defs1)
        for (MCRegister use : uses2)
            if (def == use)
                dependencies.emplace_back(
                    DependencyType(RegisterOperand(def), RegisterOperand(use)));

    // repeat for memory accesses
    for (int64_t def : memOffsets1)
        for (int64_t use : memOffsets2)
            if (def == use)
                dependencies.emplace_back(
                    DependencyType(RegisterOperand(def), RegisterOperand(use)));

    return dependencies;
}

std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg) {
    ErrorCode ec;
    // we dont want to save sub registers
    std::tie(ec, Reg) = getSupermostRegister(Reg);
    if (ec != SUCCESS) return {ec, ""};
    std::string result;
    llvm::raw_string_ostream os(result); // Wrap with raw_ostream

    if (getEnv().isX86()) {
        MCInst inst;
        inst.setOpcode(getEnv().getOpcode("PUSH64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, os);
        os << "\n";
        return {SUCCESS, result};
    }
    if (getEnv().isAArch64()) return {SUCCESS, ""}; // all registers saved in template
    if (getEnv().isRISCV()) return {SUCCESS, ""};   // all registers saved in template
    return {E_UNSUPPORTED_ARCH, ""};
}

std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg) {
    ErrorCode ec;
    std::tie(ec, Reg) = getSupermostRegister(Reg);
    if (ec != SUCCESS) return {ec, ""};
    std::string result;
    llvm::raw_string_ostream os(result);

    if (getEnv().isX86()) {
        MCInst inst;
        inst.setOpcode(getEnv().getOpcode("POP64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, os);
        os << "\n";
        return {SUCCESS, result};
    }
    if (getEnv().isAArch64()) return {SUCCESS, ""}; // all registers restored in template
    if (getEnv().isRISCV()) return {SUCCESS, ""};   // all registers restored in template
    return {E_UNSUPPORTED_ARCH, ""};
}

template <typename T> std::string genSetRegister(MCRegister Reg, T Value) {
    // this might be called with no value for Reg, as memory operands are made up of registers
    // and immediates and registers in memory operands might be empty
    if (Reg == 0) {
        return "";
    }
    std::string result;
    llvm::raw_string_ostream os(result);
    for (RegInitTemplate regTemplate : getTemplate().regInitTemplates) {
        MCRegisterClass movClass = getEnv().MRI->getRegClass(regTemplate.targetRegisterClassID);
        if (!getEnv().regInRegClass(Reg, movClass)) {
            // this can not be used by the template directly, check if the register has any
            // superregister that can be used by the template
            for (MCRegister superReg : getEnv().TRI->superregs(Reg)) {
                if (getEnv().regInRegClass(superReg, movClass)) {
                    dbg(__func__, "initializing superregister ", superReg, " instead of ", Reg);
                    return genSetRegister(superReg, Value);
                }
            }
            continue; // template cannot initialize this register
        }

        if (regTemplate.dependencyReg) {
            // this instruction needs another register to be initialized first
            std::string dependencyString = genSetRegister(regTemplate.dependencyReg.value(), Value);
            if (dependencyString == "") return "";
            os << dependencyString;
        }
        // insert immediate and register into template
        os << regTemplate.fillRegInitTemplate(Reg, Value);
        return result;
    }
    return "";
}

std::string genRegInitCode(std::vector<MCInst> Instructions, uint64_t RegInitValue) {
    // override some register types
    std::map<unsigned, std::variant<uint32_t, uint64_t, float, double>> regInitMap;
    if (getEnv().isX86()) {
        regInitMap = {
            {X86::VK8WMRegClassID, uint32_t{0b11111111}}, // x86 mask register
            // {X86::GR32RegClassID, float(7.0)},
            // {X86::VR512RegClassID, double{5}},
        };
    } // TODO

    std::string regInit;
    llvm::raw_string_ostream rio(regInit);
    std::set<MCRegister> initialized;
    for (auto inst : Instructions) {
        const MCInstrDesc &desc = getEnv().MCII->get(inst.getOpcode());
        // initialize all registers used by the instructions
        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
            // need to check using MCOI because there are registers hiding in memory operands and
            // initialising those will break the memory accesses
            if (desc.operands()[i].OperandType != MCOI::OPERAND_REGISTER) continue;
            MCRegister reg = inst.getOperand(i).getReg();
            if (initialized.find(reg) != initialized.end()) continue;

            auto regClasses = getEnv().getRegClasses(reg);
            auto it = regInitMap.find(0);
            for (auto regClass : regClasses) {
                it = regInitMap.find(regClass.getID());
                if (it != regInitMap.end()) break;
            }

            if (it == regInitMap.end()) {
                rio << genSetRegister(reg, RegInitValue); // use default/user defined value
            } else {
                rio << std::visit([reg](auto &&Value) { return genSetRegister(reg, Value); },
                                  regInitMap.at(it->first));
            }

            initialized.insert(reg);
        }
    }
    return regInit;
}

ErrorCode isValid(unsigned Opcode) {
    const MCInstrDesc &desc = getEnv().MCII->get(Opcode);
    if (desc.isPseudo()) return S_PSEUDO_INSTRUCTION;
    if (!includeMemory) {
        if (desc.mayLoad()) return S_MAY_LOAD;
        if (desc.mayStore()) return S_MAY_STORE;
        for (auto op : desc.operands())
            if (op.OperandType == MCOI::OPERAND_MEMORY) return S_MEMORY_OPERAND;
    }
    if (!includeNonMemory) {
        if (!desc.mayLoad() && !desc.mayStore()) return S_NON_MEMORY;
    }
    if (desc.isCall()) return S_IS_CALL;
    if (desc.isMetaInstruction()) return S_IS_META_INSTRUCTION;
    if (desc.isReturn()) return S_IS_RETURN;
    if (desc.isBranch()) return S_IS_BRANCH; // TODO uops has TP, how?
    if (!includeX87FP && getEnv().isX86() && desc.hasImplicitDefOfPhysReg(X86::FPSW))
        return S_IS_X87FP;
    if (!includeNonX87FP && getEnv().isX86() && !desc.hasImplicitDefOfPhysReg(X86::FPSW))
        return S_IS_NON_X87FP;
    for (auto op : desc.operands())
        if (op.OperandType == MCOI::OPERAND_PCREL) return S_PCREL_OPERAND;

    // blacklist instructions writing to certain registers
    // on AArch64 writing LR can indeterministicly lead to very long runtimes or get trapped
    // (didn't test which one)
    // in general everything modifying the stack pointer will break
    std::vector<MCRegister> registerBlacklist;
    if (getEnv().isX86())
        registerBlacklist = {X86::RSP};
    else if (getEnv().isAArch64())
        registerBlacklist = {AArch64::LR};

    ArrayRef<MCPhysReg> defs = desc.implicit_defs();
    for (MCRegister reg : registerBlacklist) {
        if (std::find(defs.begin(), defs.end(), reg) != defs.end()) {
            return S_BLACKLISTED_REGISTER;
        }
    }
    MCInst inst;
    inst.setOpcode(desc.getOpcode());
    auto [iName, _] = getEnv().MIP->getMnemonic(inst);
    if (!iName) return S_NO_MNEMONIC;
    // if (X86II::isPrefix(Instruction.TSFlags)) return INSTRUCION_PREFIX;
    // TODO some instructions have isCodeGenOnly flag, how to check it?
    // TODO some pseudo instructions are not marked as pseudo (ABS_Fp32)
    return SUCCESS;
}

} // namespace winic
