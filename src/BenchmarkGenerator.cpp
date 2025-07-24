#include "BenchmarkGenerator.h"

#include "AssemblyFile.h"
#include "CustomDebug.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "LLVMEnvironment.h"
#include "MCTargetDesc/AArch64MCTargetDesc.h"
#include "MCTargetDesc/RISCVMCTargetDesc.h"
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
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <llvm/IR/Value.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <memory>
#include <optional>

std::vector<LatMeasurement> genLatMeasurements(unsigned MinOpcode, unsigned MaxOpcode,
                                               std::unordered_set<unsigned> OpcodeBlacklist) {
    dbg(__func__, "MinOpcode: ", MinOpcode, " MaxOpcode: ", MaxOpcode,
        " OpcodeBlacklist.size(): ", OpcodeBlacklist.size());
    if (MaxOpcode == 0) MaxOpcode = getEnv().MCII->getNumOpcodes();
    // generate a function for each read write dependency combination possible

    std::vector<LatMeasurement> measurements;
    for (unsigned opcode = MinOpcode; opcode < MaxOpcode; opcode++) {
        if (OpcodeBlacklist.find(opcode) != OpcodeBlacklist.end()) continue;
        const MCInstrDesc &desc = getEnv().MCII->get(opcode);
        ErrorCode ec = isValid(desc);
        if (ec != SUCCESS) {
            dbg(__func__, getEnv().MCII->getName(opcode).data(), " skipped for reason ",
                ecToString(ec));
            continue;
        }
        auto operands = desc.operands();

        for (unsigned i = 0; i < desc.getNumDefs(); i++) {
            auto defOperand = operands[i];
            // normal use -> normal def
            for (unsigned j = desc.getNumDefs(); j < operands.size(); j++) {
                auto useOperand = operands[j];
                if (useOperand.OperandType != MCOI::OPERAND_REGISTER) continue;
                LatMeasurement m =
                    LatMeasurement(opcode,
                                   DependencyType(Operand::fromRegClass(defOperand.RegClass),
                                                  Operand::fromRegClass(useOperand.RegClass)),
                                   i, j);
                measurements.emplace_back(m);
            }
            // implUse -> normal def
            auto implUses = desc.implicit_uses();
            for (unsigned j = 0; j < implUses.size(); j++) {
                MCRegister useReg = implUses[j];
                LatMeasurement m =
                    LatMeasurement(opcode,
                                   DependencyType(Operand::fromRegClass(defOperand.RegClass),
                                                  Operand::fromRegister(useReg)),
                                   i, 999);
                measurements.emplace_back(m);
            }
        }
        auto implDefs = desc.implicit_defs();
        for (unsigned i = 0; i < implDefs.size(); i++) {
            MCRegister defReg = implDefs[i];
            // normal Use -> implDef
            for (unsigned j = desc.getNumDefs(); j < operands.size(); j++) {
                auto useOperand = operands[j];
                if (useOperand.OperandType != MCOI::OPERAND_REGISTER) continue;
                auto m = LatMeasurement(opcode,
                                        DependencyType(Operand::fromRegister(defReg),
                                                       Operand::fromRegClass(useOperand.RegClass)),
                                        999, j);

                measurements.emplace_back(m);
            }
            // implUse -> implDef
            auto implUses = desc.implicit_uses();
            for (unsigned j = 0; j < implUses.size(); j++) {
                MCRegister useReg = implUses[j];
                auto m = LatMeasurement(
                    opcode,
                    DependencyType(Operand::fromRegister(defReg), Operand::fromRegister(useReg)),
                    999, 999);

                measurements.emplace_back(m);
            }
        }
    }
    return measurements;
}

std::pair<ErrorCode, AssemblyFile> genLatBenchmark(const std::list<LatMeasurement> &Measurements,
                                                   unsigned *TargetInstrCount,
                                                   std::set<MCRegister> UsedRegisters) {
    dbg(__func__, "Measurements.size(): ", Measurements.size(),
        " TargetInstrCount: ", *TargetInstrCount, " UsedRegisters.size(): ", UsedRegisters.size());
    auto benchTemplate = getTemplate(getEnv().MSTI->getTargetTriple().getArch());
    // extract list of registers used by the template
    for (unsigned i = 0; i < getEnv().MRI->getNumRegs(); i++) {
        MCRegister reg = MCRegister::from(i);
        if (benchTemplate.usedRegisters.find(getEnv().TRI->getRegAsmName(reg).lower().data()) !=
            benchTemplate.usedRegisters.end())
            UsedRegisters.insert(reg);
    }
    std::map<unsigned, MCRegister> chosenRegisters;
    // generate an instruction for every measurement
    std::vector<MCInst> instructions;
    for (auto m : Measurements) {
        std::map<unsigned, MCRegister> constraints;
        // choose registers for the operands building the latency chain
        for (auto [opIndex, op] :
             {std::make_pair(m.defIndex, m.type.defOp), std::make_pair(m.useIndex, m.type.useOp)}) {
            if (op.isRegClass()) {
                // currently only the class is known, we have to specify which register to
                // use for generating the instruciton
                unsigned regClassID = op.getRegClass();
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
            } else // implicit def/use -> this provides a register directly
                UsedRegisters.insert(op.getRegister());
        }

        auto [EC, instruction] = genInst(m.opcode, constraints, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        instructions.emplace_back(instruction);
    }

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
    std::set<MCRegister> initialized;
    for (auto inst : instructions) {
        // initialize all registers used by the instructions
        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
            if (!inst.getOperand(i).isReg()) continue;
            MCRegister reg = inst.getOperand(i).getReg();
            if (initialized.find(reg) == initialized.end()) {
                rio << genSetRegister(reg, 4);
                initialized.insert(reg);
            }
        }
        // execute each instruction once in the init function to e.g. mark registers as avx
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, ico);
        ico << "\n";
    }
    ico << restoreRegs << "\n";

    AssemblyFile assemblyFile(getEnv().Arch);
    assemblyFile.addInitFunction("init", initCode);
    assemblyFile.addBenchFunction("lat", saveRegs + regInit, loopCode, restoreRegs, "init");
    assemblyFile.addBenchFunction("lat2", saveRegs + regInit, loopCode + loopCode, restoreRegs,
                                  "init");

    // check if each instruction of the sequence has exactly one dependency to the next one.
    // otherwise return a warning
    for (size_t i = 0; i < instructions.size() - 1; i++)
        if (getDependencies(instructions[i], instructions[i + 1]).size() != 1)
            return {W_MULTIPLE_DEPENDENCIES, assemblyFile};

    if (getDependencies(instructions[instructions.size() - 1], instructions[0]).size() != 1)
        return {W_MULTIPLE_DEPENDENCIES, assemblyFile};

    return {SUCCESS, assemblyFile};
}

std::pair<ErrorCode, AssemblyFile> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                  unsigned UnrollCount,
                                                  std::set<MCRegister> UsedRegisters,
                                                  std::map<unsigned, MCRegister> HelperConstraints,
                                                  unsigned HelperOpcode) {
    dbg(__func__, "Opcode: ", Opcode, " Name: ", getEnv().MCII->getName(Opcode).str(),
        " TargetInstrCount: ", *TargetInstrCount, " UnrollCount: ", UnrollCount,
        " UsedRegisters.size(): ", UsedRegisters.size(),
        " HelperConstraints.size(): ", HelperConstraints.size());
    if (HelperOpcode != MAX_UNSIGNED)
        dbg(__func__, "Helper: ", getEnv().MCII->getName(HelperOpcode).data());
    auto benchTemplate = getTemplate(getEnv().MSTI->getTargetTriple().getArch());
    // extract list of registers used by the template
    // TODO optimize
    for (unsigned i = 0; i < getEnv().MRI->getNumRegs(); i++) {
        MCRegister reg = MCRegister::from(i);
        if (benchTemplate.usedRegisters.find(getEnv().TRI->getRegAsmName(reg).lower().data()) !=
            benchTemplate.usedRegisters.end()) {
            UsedRegisters.insert(reg);
        }
    }

    // this is the hepler instruciton if needed.
    std::list<MCInst> instructions;
    ErrorCode EC;
    if (HelperOpcode != MAX_UNSIGNED) {
        std::tie(EC, instructions) = genTPLoop({Opcode, HelperOpcode}, {{}, HelperConstraints},
                                               *TargetInstrCount, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        // update TargetInstructionCount to actual number of instructions generated, dont include
        // helper instructions
        *TargetInstrCount = UnrollCount * instructions.size() / 2;
    } else {
        // ho helper
        std::tie(EC, instructions) = genTPLoop({Opcode}, {{}}, *TargetInstrCount, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        // update TargetInstructionCount to actual number of instructions generated
        *TargetInstrCount = UnrollCount * instructions.size();
    }

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
    std::string regInit;
    std::string singleLoopCode;
    llvm::raw_string_ostream rio(regInit);
    llvm::raw_string_ostream slo(singleLoopCode);
    std::set<MCRegister> initialized;
    for (auto inst : instructions) {
        // initialize all registers used by the instructions
        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
            if (!inst.getOperand(i).isReg()) continue;
            MCRegister reg = inst.getOperand(i).getReg();
            if (initialized.find(reg) == initialized.end()) {
                rio << genSetRegister(reg, 4);
                initialized.insert(reg);
            }
        }
        // build loop code
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, slo);
        slo << "\n";
    }

    std::string loopCode;
    for (unsigned i = 0; i < UnrollCount; i++)
        loopCode.append(singleLoopCode);

    std::string initCode = saveRegs + singleLoopCode + restoreRegs + "\n";

    AssemblyFile assemblyFile(getEnv().Arch);
    assemblyFile.addInitFunction("init", initCode);
    assemblyFile.addBenchFunction("tp", saveRegs + regInit, loopCode, restoreRegs, "init");
    assemblyFile.addBenchFunction("tp2", saveRegs+ regInit, loopCode + loopCode, restoreRegs, "init");
    return {SUCCESS, assemblyFile};
}

std::pair<ErrorCode, std::list<MCInst>>
genTPLoop(std::vector<unsigned> Opcodes,
          std::vector<std::map<unsigned, MCRegister>> ConstraintsVector, unsigned TargetInstrCount,
          std::set<MCRegister> &UsedRegisters) {
    std::list<MCInst> instructions;
    for (unsigned i = 0; i < Opcodes.size(); i++) {
        unsigned opcode = Opcodes[i];
        const MCInstrDesc &desc = getEnv().MCII->get(opcode);
        // this is the first generated instruction, all other instructions will use the
        // same registers as this one if they are only read
        auto [EC, refInst] = genInst(opcode, ConstraintsVector[i], UsedRegisters);
        if (EC != SUCCESS) return {EC, instructions};
        instructions.push_back(refInst);

        // constrain all other instructions of this opcode to use the same use registers as the
        // first one
        for (unsigned opIndex = desc.getNumDefs(); opIndex < desc.getNumOperands(); opIndex++) {
            auto op = desc.operands()[opIndex];
            if (op.OperandType == MCOI::OPERAND_REGISTER)
                ConstraintsVector[i].insert({opIndex, refInst.getOperand(opIndex).getReg()});
        }
    }

    for (unsigned i = 1; i < TargetInstrCount; ++i) {
        // only insert complete sets of instructions into the final list. (Registers may run out mid
        // generation)
        std::list<MCInst> tempInstructions;
        for (unsigned j = 0; j < Opcodes.size(); j++) {
            auto [EC, inst] = genInst(Opcodes[j], ConstraintsVector[j], UsedRegisters);
            if (EC == E_NO_REGISTERS) return {SUCCESS, instructions}; // shorter loops are ok
            if (EC != SUCCESS) return {EC, {instructions}};
            tempInstructions.push_back(inst);
        }
        instructions.insert(instructions.end(), tempInstructions.begin(), tempInstructions.end());
    }
    return {SUCCESS, instructions};
}

std::tuple<ErrorCode, int> whichOperandCanUse(unsigned Opcode, std::string Type,
                                              MCRegister RequiredRegister) {
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
        errs() << "choose between use and def\n";
        return {E_UNREACHABLE, 0};
    }
    return {E_GENERIC, 0};
}

std::pair<ErrorCode, MCInst> genInst(unsigned Opcode, std::map<unsigned, MCRegister> Constraints,
                                     std::set<MCRegister> &UsedRegisters, unsigned Immediate) {
    const MCInstrDesc &desc = getEnv().MCII->get(Opcode);
    unsigned numOperands = desc.getNumOperands();
    std::set<MCRegister> localUsedRegisters;

    // make sure fixed registers are not used anywhere else than they are supposed to by adding
    // them to usedRegisters beforehand
    for (auto c : Constraints)
        localUsedRegisters.insert(c.second);

    MCInst inst;
    inst.setOpcode(Opcode);
    inst.clear();
    // fill every operand of the instruction with a valid reg/imm
    for (unsigned j = 0; j < numOperands; ++j) {
        const MCOperandInfo &opInfo = desc.operands()[j];
        // TIED_TO points to operand which this has to be identical to.
        // see MCInstrDesc.h:41
        if (opInfo.Constraints & (1 << MCOI::TIED_TO)) {
            // this operand must be identical to another operand
            unsigned tiedToOp = (opInfo.Constraints >> (4 + MCOI::TIED_TO * 4)) & 0xF;
            inst.addOperand(inst.getOperand(tiedToOp));
            if (inst.getOperand(tiedToOp).isReg()) {
                MCRegister reg = inst.getOperand(tiedToOp).getReg();
                localUsedRegisters.insert(reg);
            }
        } else {
            switch (opInfo.OperandType) {
            case MCOI::OPERAND_REGISTER: {
                // check if Constraints force registers for this operand
                if (Constraints.find(j) != Constraints.end()) {
                    inst.addOperand(MCOperand::createReg(Constraints[j]));
                    break;
                }

                const MCRegisterClass &regClass = getEnv().MRI->getRegClass(opInfo.RegClass);
                // search for unused register and add it as this operand
                bool foundRegister = false;
                for (MCRegister reg : regClass) {
                    if ((getEnv().Arch == Triple::ArchType::x86_64 && reg.id() == 58) ||
                        reg.id() >= getEnv().MaxReg)
                        // TODO replace with check for arch and X86::RAX
                        // RIP register (58) is included in GR64 class which is a bug
                        // see X86RegisterInfo.td:586
                        continue;
                    // don't use this if sub- or superregisters are in usedRegisters
                    if (std::any_of(
                            UsedRegisters.begin(), UsedRegisters.end(),
                            [reg](MCRegister R) { return getEnv().TRI->regsOverlap(reg, R); }))
                        continue;

                    // don't reuse any registers
                    if (std::any_of(
                            localUsedRegisters.begin(), localUsedRegisters.end(),
                            [reg](MCRegister R) { return getEnv().TRI->regsOverlap(reg, R); }))
                        continue;

                    inst.addOperand(MCOperand::createReg(reg));
                    localUsedRegisters.insert(reg);
                    foundRegister = true;
                    break;
                }
                if (!foundRegister) return {E_NO_REGISTERS, {}};

                break;
            }
            case MCOI::OPERAND_IMMEDIATE:
                inst.addOperand(MCOperand::createImm(Immediate));
                break;
            case MCOI::OPERAND_MEMORY:
                return {S_MEMORY_OPERAND, {}};
            case MCOI::OPERAND_PCREL:
                return {S_PCREL_OPERAND, {}};
            default:
                // especially on aarch64 many types of immediates have operand type UNKNOWN_OPERAND
                // (idk why) speculatively plug in immediates and hope for the best (e.g. ADDXri
                // cannot be generated without this)
                inst.addOperand(MCOperand::createImm(Immediate));
            }
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
    return {E_UNREACHABLE, NULL};
}

std::pair<ErrorCode, MCRegister> getFreeRegisterInClass(const MCRegisterClass &RegClass,
                                                        std::set<MCRegister> UsedRegisters) {
    for (auto reg : RegClass)
        if (UsedRegisters.find(reg) == UsedRegisters.end()) return {SUCCESS, reg};
    return {E_NO_REGISTERS, MAX_UNSIGNED};
}

std::pair<ErrorCode, MCRegister> getFreeRegisterInClass(unsigned RegClassID,
                                                        std::set<MCRegister> UsedRegisters) {
    const MCRegisterClass &regClass = getEnv().MRI->getRegClass(RegClassID);
    return getFreeRegisterInClass(regClass, UsedRegisters);
}

std::list<DependencyType> getDependencies(MCInst Inst1, MCInst Inst2) {
    std::list<DependencyType> dependencies;
    const MCInstrDesc &desc1 = getEnv().MCII->get(Inst1.getOpcode());
    const MCInstrDesc &desc2 = getEnv().MCII->get(Inst2.getOpcode());
    // collect all registers Inst1 will define
    std::set<MCRegister> defs1;
    for (unsigned i = 0; i < desc1.getNumDefs() && i < Inst1.getNumOperands(); i++) {
        if (Inst1.getOperand(i).isReg()) defs1.insert(Inst1.getOperand(i).getReg());
    }
    for (MCRegister implDef : desc1.implicit_defs()) {
        defs1.insert(implDef);
    }
    // collect all registers Inst2 will use
    std::set<MCRegister> uses2;
    for (unsigned i = desc2.getNumDefs(); i < desc2.getNumOperands(); i++) {
        if (Inst2.getOperand(i).isReg()) uses2.insert(Inst2.getOperand(i).getReg());
    }
    for (MCRegister implUse : desc2.implicit_uses()) {
        uses2.insert(implUse);
    }
    // create dependencyType for every register which is defined by 1 and used by 2
    for (MCRegister def : defs1)
        for (MCRegister use : uses2)
            if (def == use)
                dependencies.emplace_back(
                    DependencyType(Operand::fromRegister(def), Operand::fromRegister(use)));
    return dependencies;
}

std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg) {
    ErrorCode ec;
    // we dont want to save sub registers
    std::tie(ec, Reg) = getSupermostRegister(Reg);
    if (ec != SUCCESS) return {ec, ""};
    std::string result;
    llvm::raw_string_ostream os(result); // Wrap with raw_ostream

    switch (getEnv().Arch) {
    case llvm::Triple::x86_64: {
        MCInst inst;
        inst.setOpcode(getEnv().getOpcode("PUSH64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, os);
        os << "\n";
        break;
    }
    case llvm::Triple::aarch64:
        return {SUCCESS, ""}; // all registers saved in template
    case llvm::Triple::riscv64:
        return {SUCCESS, ""}; // all registers saved in template
    default:
        return {E_UNSUPPORTED_ARCH, ""};
    }

    return {SUCCESS, result};
}

std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg) {
    ErrorCode ec;
    std::tie(ec, Reg) = getSupermostRegister(Reg);
    if (ec != SUCCESS) return {ec, ""};
    std::string result;
    llvm::raw_string_ostream os(result);

    switch (getEnv().Arch) {
    case llvm::Triple::x86_64: {
        MCInst inst;
        inst.setOpcode(getEnv().getOpcode("POP64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, os);
        os << "\n";
        break;
    }
    case llvm::Triple::aarch64:
        return {SUCCESS, ""}; // all registers restored in template
    case llvm::Triple::riscv64:
        return {SUCCESS, ""}; // all registers restored in template
    default:
        return {E_UNSUPPORTED_ARCH, ""};
    }
    return {SUCCESS, result};
}

std::string genSetRegister(MCRegister Reg, unsigned Value) {
    std::string result;
    llvm::raw_string_ostream os(result);
    // a way to move the immediate into the register, may also be a chain of instructions
    struct Solution {
        MCInst inst;
        // set this if another register is needed for staging
        std::optional<MCRegister> dependencyReg;
    };
    // instructions in this list are tried in order
    std::vector<Solution> solutions;

    switch (getEnv().Arch) {
    case llvm::Triple::x86_64: {
        Solution solution1;
        solution1.inst.setOpcode(X86::MOV64ri32); // GR64
        solution1.inst.addOperand(MCOperand::createReg(Reg));
        solution1.inst.addOperand(MCOperand::createImm(Value));
        solutions.emplace_back(solution1);
        Solution solution2;
        solution2.inst.setOpcode(X86::MOVDI2PDIrr); // VR128
        solution2.inst.addOperand(MCOperand::createReg(Reg));
        solution2.inst.addOperand(MCOperand::createReg(X86::EAX));
        solution2.inst.addOperand(MCOperand::createImm(Value));
        solution2.dependencyReg = X86::EAX;
        solutions.emplace_back(solution2);
        break;
    }
    case llvm::Triple::aarch64: {
        Solution solution1;
        solution1.inst.setOpcode(AArch64::MOVZXi); // GPR64
        solution1.inst.addOperand(MCOperand::createReg(Reg));
        solution1.inst.addOperand(MCOperand::createImm(Value));
        solution1.inst.addOperand(MCOperand::createImm(0));
        solutions.emplace_back(solution1);
        Solution solution2;
        solution2.inst.setOpcode(AArch64::MOVID); // FPR64
        solution2.inst.addOperand(MCOperand::createReg(Reg));
        solution2.inst.addOperand(MCOperand::createImm(Value));
        solutions.emplace_back(solution2);
        break;
    }
    case llvm::Triple::riscv64: {
        Solution solution1;
        solution1.inst.setOpcode(RISCV::ADDI); // GPR
        solution1.inst.addOperand(MCOperand::createReg(Reg));
        solution1.inst.addOperand(MCOperand::createReg(RISCV::X0));
        solution1.inst.addOperand(MCOperand::createImm(Value));
        solutions.emplace_back(solution1);
        Solution solution2;
        solution2.inst.setOpcode(RISCV::FMV_W_X); // FPR32
        solution2.inst.addOperand(MCOperand::createReg(Reg));
        solution2.inst.addOperand(MCOperand::createReg(RISCV::X10));
        solution1.inst.addOperand(MCOperand::createImm(Value));
        solution2.dependencyReg = RISCV::X10;
        solutions.emplace_back(solution2);
        Solution solution3;
        solution3.inst.setOpcode(RISCV::VMV_V_I); // VR
        solution3.inst.addOperand(MCOperand::createReg(Reg));
        solution3.inst.addOperand(MCOperand::createImm(Value));
        solutions.emplace_back(solution3);
        break;
    }
    default:
        return "";
    }

    for (Solution solution : solutions) {
        // find register class of move operation
        const MCInstrDesc &desc = getEnv().MCII->get(solution.inst.getOpcode());
        unsigned movClassID = desc.operands()[0].RegClass;
        MCRegisterClass movClass = getEnv().MRI->getRegClass(movClassID);
        if (!getEnv().regInRegClass(Reg, movClass)) {
            // this can not be used by mov directly, check if the register has any superregister
            // that can be used by the mov
            for (MCRegister superReg : getEnv().TRI->superregs(Reg)) {
                auto [EC, cl] = getEnv().getRegClass(superReg);
                if (EC != SUCCESS) continue;
                if (getEnv().regInRegClass(superReg, movClass)) {
                    dbg(__func__, "initializing superregister ", getEnv().regToString(superReg),
                        " instead of ", getEnv().regToString(Reg));
                    return genSetRegister(superReg, Value);
                }
            }
            continue; // solution cannot initialize this register
        }
        if (solution.dependencyReg) {
            // this instruction needs another register to be initialized first
            std::string dependencyString = genSetRegister(solution.dependencyReg.value(), Value);
            if (dependencyString == "") return "";
            os << dependencyString;
        }
        getEnv().MIP->printInst(&solution.inst, 0, "", *getEnv().MSTI, os);
        os << "\n";
        return result;
    }
    return "";
}

ErrorCode isValid(const MCInstrDesc &Desc) {
    dbg(__func__, "Opcode: ", Desc.getOpcode(),
        " Name: ", getEnv().MCII->getName(Desc.getOpcode()).data());
    if (Desc.isPseudo()) return S_PSEUDO_INSTRUCTION;
    if (Desc.mayLoad()) return S_MAY_LOAD;
    if (Desc.mayStore()) return S_MAY_STORE;
    if (Desc.isCall()) return S_IS_CALL;
    if (Desc.isMetaInstruction()) return S_IS_META_INSTRUCTION;
    if (Desc.isReturn()) return S_IS_RETURN;
    if (Desc.isBranch()) return S_IS_BRANCH; // TODO uops has TP, how?
    if (!includeX87FP && getEnv().Arch == Triple::ArchType::x86_64 &&
        Desc.hasImplicitDefOfPhysReg(X86::FPSW))
        return S_IS_X87FP;
    MCInst inst;
    inst.setOpcode(Desc.getOpcode());
    auto [iName, _] = getEnv().MIP->getMnemonic(inst);
    if (!iName) return S_NO_MNEMONIC;
    // if (X86II::isPrefix(Instruction.TSFlags)) return INSTRUCION_PREFIX;
    // TODO some instructions have isCodeGenOnly flag, how to check it?
    // TODO some pseudo instructions are not marked as pseudo (ABS_Fp32)
    return SUCCESS;
}
