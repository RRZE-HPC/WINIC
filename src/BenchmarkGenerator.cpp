
#include "BenchmarkGenerator.h"

#include "AssemblyFile.h" // for AssemblyFile, replaceAl...
#include "CustomDebug.h"  // for dbg
#include "ErrorCode.h"    // for ErrorCode, ecToString
#include "Globals.h"      // for env, LatMeasurement
#include "LLVMBench.h"
#include "LLVMEnvironment.h" // for LLVMEnvironment
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "Templates.h"                       // for Template, getTemplate
#include "llvm/ADT/ArrayRef.h"               // for ArrayRef
#include "llvm/ADT/StringRef.h"              // for StringRef
#include "llvm/ADT/iterator_range.h"         // for iterator_range
#include "llvm/CodeGen/TargetRegisterInfo.h" // for TargetRegisterInfo
#include "llvm/MC/MCInst.h"                  // for MCInst, MCOperand
#include "llvm/MC/MCInstPrinter.h"           // for MCInstPrinter
#include "llvm/MC/MCInstrDesc.h"             // for MCInstrDesc, MCOperandInfo
#include "llvm/MC/MCInstrInfo.h"             // for MCInstrInfo
#include "llvm/MC/MCRegister.h"              // for MCRegister
#include "llvm/MC/MCSubtargetInfo.h"         // for MCSubtargetInfo
#include "llvm/Support/raw_ostream.h"        // for raw_string_ostream, raw...
#include "llvm/TargetParser/Triple.h"        // for Triple
#include <algorithm>                         // for any_of
#include <cstddef>                           // for NULL
#include <initializer_list>                  // for initializer_list
#include <memory>                            // for unique_ptr

std::string genRegInit(MCRegister Reg, std::string InitValue, Template BenchTemplate) {
    std::string regName = getEnv().TRI->getRegAsmName(Reg).lower().data();
    for (auto a : BenchTemplate.regInitTemplates) {
        if (regName.find(a.first) != std::string::npos || a.first == "default") {
            if (a.second == "None") break; // template says this should not be initialized
            if (getEnv().Arch == llvm::Triple::aarch64 && a.first != "default") {
                // change reg name from e.g. q2 -> v2
                regName = regName.replace(0, 1, "v");
            }
            std::string init = replaceAllInstances(a.second, "reg", regName) + "\n";
            init = replaceAllInstances(init, "imm", InitValue);
            return init;
        }
    }
    return "";
}

std::vector<LatMeasurement> genLatMeasurements(unsigned MinOpcode, unsigned MaxOpcode,
                                               std::unordered_set<unsigned> SkipOpcodes) {
    if (MaxOpcode == 0) MaxOpcode = getEnv().MCII->getNumOpcodes();
    // generate a function for each read write dependency combination possible

    std::vector<LatMeasurement> measurements;
    for (unsigned opcode = MinOpcode; opcode < MaxOpcode; opcode++) {
        if (SkipOpcodes.find(opcode) != SkipOpcodes.end()) continue;
        // if (Opcode != getOpcode("AND8rr_ND")) continue;
        const MCInstrDesc &desc = getEnv().MCII->get(opcode);
        ErrorCode ec = isValid(desc);
        if (ec != SUCCESS) {
            dbg(__func__, getEnv().MCII->getName(opcode).data(), " skipped for reason ", ecToString(ec));
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
                dbg(__func__, "adding ", m);
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
                dbg(__func__, "adding ", m);
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
                dbg(__func__, "adding ", m);
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
                dbg(__func__, "adding ", m);
            }
        }
    }
    return measurements;
}

std::pair<ErrorCode, AssemblyFile> genLatBenchmark(const std::list<LatMeasurement> &Measurements,
                                                   unsigned *TargetInstrCount,
                                                   std::set<MCRegister> UsedRegisters) {
    dbg(__func__, "generating latency benchmark");
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

    dbg(__func__, "printing");

    std::string loopCode;
    llvm::raw_string_ostream lco(loopCode);
    for (unsigned i = 0; i < *TargetInstrCount; ++i) {
        for (auto inst : instructions) {
            getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, lco);
            lco << "\n";
        }
    }
    dbg(__func__, "inti code");
    std::string initCode;
    llvm::raw_string_ostream ico(initCode);
    ico << saveRegs << "\n";
    for (auto inst : instructions) {
        // initialize all registers used by the instructions
        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
            if (!inst.getOperand(i).isReg()) continue;
            MCRegister reg = inst.getOperand(i).getReg();
            ico << genRegInit(reg, "0x4", benchTemplate);
        }
        // execute each instruction once in the init function to e.g. mark registers as avx
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, ico);
        ico << "\n";
    }
    ico << restoreRegs << "\n";

    dbg(__func__, "assembly file");
    AssemblyFile assemblyFile(getEnv().Arch);
    assemblyFile.addInitFunction("init", initCode);
    assemblyFile.addBenchFunction("latency", saveRegs, loopCode, restoreRegs, "init");
    assemblyFile.addBenchFunction("latencyUnrolled", saveRegs, loopCode + loopCode, restoreRegs,
                                  "init");
    dbg(__func__, "checking deps");

    // check if each instruction of the sequence has exactly one dependency to the next one.
    // otherwise return a warning
    for (size_t i = 0; i < instructions.size() - 1; i++)
        if (getDependencies(instructions[i], instructions[i + 1]).size() != 1)
            return {WARNING_MULTIPLE_DEPENDENCIES, assemblyFile};

    if (getDependencies(instructions[instructions.size() - 1], instructions[0]).size() != 1)
        return {WARNING_MULTIPLE_DEPENDENCIES, assemblyFile};

    return {SUCCESS, assemblyFile};
}

std::pair<ErrorCode, AssemblyFile> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                  unsigned UnrollCount,
                                                  std::set<MCRegister> UsedRegisters,
                                                  std::map<unsigned, MCRegister> HelperConstraints,
                                                  unsigned HelperOpcode) {
    // TODO change to list of opcodes
    dbg(__func__, "getting template");
    auto benchTemplate = getTemplate(getEnv().MSTI->getTargetTriple().getArch());
    // extract list of registers used by the template
    // TODO optimize
    dbg(__func__, "getting usedRegs");
    for (unsigned i = 0; i < getEnv().MRI->getNumRegs(); i++) {
        MCRegister reg = MCRegister::from(i);
        if (benchTemplate.usedRegisters.find(getEnv().TRI->getRegAsmName(reg).lower().data()) !=
            benchTemplate.usedRegisters.end())
            UsedRegisters.insert(reg);
    }

    dbg(__func__, "call gen inner loop");

    // this is the hepler instruciton if needed.
    std::list<MCInst> instructions;
    ErrorCode EC;
    if (HelperOpcode != MAX_UNSIGNED) {
        std::tie(EC, instructions) = genTPInnerLoop({Opcode, HelperOpcode}, {{}, HelperConstraints},
                                                    *TargetInstrCount, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        // update TargetInstructionCount to actual number of instructions generated, dont include
        // helper instructions
        *TargetInstrCount = UnrollCount * instructions.size() / 2;
    } else {
        // ho helper
        std::tie(EC, instructions) =
            genTPInnerLoop({Opcode}, {{}}, *TargetInstrCount, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        // update TargetInstructionCount to actual number of instructions generated
        *TargetInstrCount = UnrollCount * instructions.size();
    }

    dbg(__func__, "inner loop generated");

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

    dbg(__func__, "starting to build benchmark code");

    std::string singleLoopCode;
    llvm::raw_string_ostream slo(singleLoopCode);
    for (auto inst : instructions) {
        getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, slo);
        slo << "\n";
    }
    std::string loopCode;
    for (unsigned i = 0; i < UnrollCount; i++)
        loopCode.append(singleLoopCode);

    std::string initCode = saveRegs + singleLoopCode + restoreRegs + "\n";

    AssemblyFile assemblyFile(getEnv().Arch);
    assemblyFile.addInitFunction("init", initCode);
    assemblyFile.addBenchFunction("tp", saveRegs, loopCode, restoreRegs, "init");
    assemblyFile.addBenchFunction("tpUnroll2", saveRegs, loopCode + loopCode, restoreRegs, "init");
    assemblyFile.addBenchFunction("tpUnroll4", saveRegs, loopCode + loopCode + loopCode + loopCode,
                                  restoreRegs, "init");
    return {SUCCESS, assemblyFile};
}

std::pair<ErrorCode, std::list<MCInst>>
genTPInnerLoop(std::vector<unsigned> Opcodes,
               std::vector<std::map<unsigned, MCRegister>> ConstraintsVector,
               unsigned TargetInstrCount, std::set<MCRegister> &UsedRegisters) {
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
            if (EC == ERROR_NO_REGISTERS) return {SUCCESS, instructions}; // shorter loops are ok
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
            dbg(__func__, "has def");
            return {SUCCESS, -1};
        }
        dbg(__func__, "doestn have def");
        for (unsigned i = 0; i < desc.getNumDefs(); i++)
            if (desc.operands()[i].OperandType == MCOI::OPERAND_REGISTER)
                if (getEnv().regInRegClass(RequiredRegister, desc.operands()[i].RegClass))
                    return {SUCCESS, i};
    } else {
        errs() << "choose between use and def\n";
        return {ERROR_UNREACHABLE, 0};
    }
    return {ERROR_GENERIC, 0};
}

std::pair<ErrorCode, MCInst> genInst(unsigned Opcode, std::map<unsigned, MCRegister> Constraints,
                                     std::set<MCRegister> &UsedRegisters) {
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
                // dbg(__func__, "using tied register: ", getEnv().TRI->getName(reg));
            }
        } else {
            switch (opInfo.OperandType) {
            case MCOI::OPERAND_REGISTER: {
                // check if Constraints force registers for this operand
                if (Constraints.find(j) != Constraints.end()) {
                    inst.addOperand(MCOperand::createReg(Constraints[j]));
                    localUsedRegisters.insert(Constraints[j]);
                    // dbg(__func__,
                    //     "using register to satisfy constraint: ",
                    //     getEnv().TRI->getName(Constraints[j]));
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
                    // dont use this if sub- or superregisters are in usedRegisters
                    if (std::any_of(UsedRegisters.begin(), UsedRegisters.end(),
                                    [reg](MCRegister R) { return getEnv().TRI->regsOverlap(reg, R); }))
                        continue;

                    // dont reuse any registers
                    if (std::any_of(localUsedRegisters.begin(), localUsedRegisters.end(),
                                    [reg](MCRegister R) { return getEnv().TRI->regsOverlap(reg, R); }))
                        continue;

                    inst.addOperand(MCOperand::createReg(reg));
                    localUsedRegisters.insert(reg);

                    // dbg(__func__, "using register: ", getEnv().TRI->getName(reg));
                    foundRegister = true;
                    break;
                }
                if (!foundRegister) return {ERROR_NO_REGISTERS, {}};

                break;
            }
            case MCOI::OPERAND_IMMEDIATE:
                inst.addOperand(MCOperand::createImm(7));
                break;
            case MCOI::OPERAND_MEMORY:
                // errs() << "instructions accessing memory are not supported at this "
                //           "time\n";
                return {MEMORY_OPERAND, {}};
            case MCOI::OPERAND_PCREL:
                // errs() << "branches are not supported at this time\n";
                return {PCREL_OPERAND, {}};
            default:
                // errs() << "unknown operand type\n";
                return {UNKNOWN_OPERAND, {}};
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
    return {ERROR_UNREACHABLE, NULL};
}

std::pair<ErrorCode, MCRegister> getFreeRegisterInClass(const MCRegisterClass &RegClass,
                                                        std::set<MCRegister> UsedRegisters) {
    for (auto reg : RegClass)
        if (UsedRegisters.find(reg) == UsedRegisters.end()) return {SUCCESS, reg};
    return {ERROR_NO_REGISTERS, MAX_UNSIGNED};
}

std::pair<ErrorCode, MCRegister> getFreeRegisterInClass(unsigned RegClassID,
                                                        std::set<MCRegister> UsedRegisters) {
    const MCRegisterClass &regClass = getEnv().MRI->getRegClass(RegClassID);
    return getFreeRegisterInClass(regClass, UsedRegisters);
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
    default:
        return {ERROR_UNSUPPORTED_ARCH, ""};
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
    default:
        return {ERROR_UNSUPPORTED_ARCH, ""};
    }
    return {SUCCESS, result};
}

ErrorCode isValid(const MCInstrDesc &Desc) {
    if (Desc.isPseudo()) return PSEUDO_INSTRUCTION;
    if (Desc.mayLoad()) return MAY_LOAD;
    if (Desc.mayStore()) return MAY_STORE;
    if (Desc.isCall()) return IS_CALL;
    if (Desc.isMetaInstruction()) return IS_META_INSTRUCTION;
    if (Desc.isReturn()) return IS_RETURN;
    if (Desc.isBranch()) return IS_BRANCH; // TODO uops has TP, how?
    if (getEnv().Arch == Triple::ArchType::x86_64 && Desc.hasImplicitDefOfPhysReg(X86::FPSW))
        return IS_X87FP;
    // if (X86II::isPrefix(Instruction.TSFlags)) return INSTRUCION_PREFIX;
    // Two more checks which only work after generating an instruction TODO find other way
    std::set<MCRegister> emptySet;
    auto [EC, inst] = genInst(Desc.getOpcode(), {}, emptySet);
    if (EC != SUCCESS) return EC;
    std::string temp;
    llvm::raw_string_ostream tso(temp);
    getEnv().MIP->printInst(&inst, 0, "", *getEnv().MSTI, tso);
    // this is very ugly, these # instructions have isCodeGenOnly flag, how can
    // we check it?
    if (temp.find("#") != std::string::npos) return IS_CODE_GEN_ONLY;

    // some pseudo instructions are not marked as pseudo (ABS_Fp32)
    if (temp.find_first_not_of('\t') == std::string::npos) return DOES_NOT_EMIT_INST;
    return SUCCESS;
}
