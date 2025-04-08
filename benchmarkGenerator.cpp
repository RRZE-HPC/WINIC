// #include "MCTargetDesc/X86BaseInfo.h"
// #include "MCTargetDesc/X86MCTargetDesc.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86RegisterInfo.h"
#include "customDebug.cpp"
// #include "customErrors.cpp"
// #include "templates.cpp"
#include "assemblyFile.cpp"
#include "llvm-c/Target.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Register.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/Triple.h"

// #include "llvm/TargetParser/X86TargetParser.h"
#include <algorithm>
#include <csetjmp>
#include <cstddef>
#include <cstdlib>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <getopt.h>
#include <list>
#include <math.h>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

using namespace llvm;

class BenchmarkGenerator {
  public:
    LLVMContext Ctx;
    Triple TargetTriple;
    std::unique_ptr<Module> Mod;
    std::unique_ptr<TargetMachine> Machine;
    std::unique_ptr<MachineFunction> MF;
    std::unique_ptr<MachineModuleInfo> MMI;
    const TargetRegisterInfo *TRI;
    // MCAsmParser *Parser;
    // MCTargetAsmParser *TAP;
    MCRegisterInfo *MRI;
    MCAsmInfo *MAI;
    MCInstrInfo *MCII;
    MCSubtargetInfo *MSTI;
    MCInstPrinter *MIP;
    // SourceMgr SrcMgr;
    // SmallVector<char> outVector;
    unsigned MaxReg;
    Triple::ArchType Arch;

    BenchmarkGenerator() : Ctx(), Mod(std::make_unique<Module>("beehives", Ctx)) {}
    ErrorCode setUp(std::string March = "", std::string Cpu = "") {

        // LLVMInitializeX86AsmParser();
        // LLVMInitializeX86Disassembler();
        // LLVMInitializeX86TargetMCA();
        // InitializeAllTargets();
        // InitializeAllTargetInfos();
        // InitializeAllTargetMCs();
        // InitializeAllAsmPrinters();
        // StringRef TargetTripleStr = "x86_64-pc-linux";
        std::string TargetTripleStr;
        if (March.empty()) {
            TargetTripleStr = llvm::sys::getDefaultTargetTriple();
        } else {
            TargetTripleStr = (March + "-pc-linux").data();
        }
        Triple TargetTriple(TargetTripleStr);

        if (Cpu.empty()) Cpu = llvm::sys::getHostCPUName().str();
        if (Cpu.empty()) return ERROR_CPU_DETECT;
        outs() << "detected " << TargetTripleStr << ", march: " << Cpu << "\n";
        outs().flush();
        if (TargetTriple.getArch() == Triple::ArchType::x86_64) {
            LLVMInitializeX86Target();
            LLVMInitializeX86TargetInfo();
            LLVMInitializeX86TargetMC();
            LLVMInitializeX86AsmPrinter();
        } else if (TargetTriple.getArch() == Triple::ArchType::aarch64) {
            LLVMInitializeAArch64Target();
            LLVMInitializeAArch64TargetInfo();
            LLVMInitializeAArch64TargetMC();
            LLVMInitializeAArch64AsmPrinter();
        } else if (TargetTriple.getArch() == Triple::ArchType::riscv64) {
            LLVMInitializeRISCVTarget();
            LLVMInitializeRISCVTargetInfo();
            LLVMInitializeRISCVTargetMC();
            LLVMInitializeRISCVAsmPrinter();
        } else {
            if (TargetTriple.getArch() != llvm::Triple::UnknownArch)
                errs() << "unsupported architecture: " << TargetTriple.getArchName() << "\n";
            return ERROR_TARGET_DETECT;
        }
        // StringRef TargetTripleStr = "x86_64--";
        // copied from InstrRefLDVTest.cpp
        Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
                           "f80:128-n8:16:32:64-S128");
        std::string Error;
        const Target *TheTarget = TargetRegistry::lookupTarget("", TargetTriple, Error);
        TargetOptions Options;
        Machine = std::unique_ptr<TargetMachine>(TheTarget->createTargetMachine(
            Triple::normalize(TargetTripleStr), Cpu, "", Options, std::nullopt, std::nullopt,
            CodeGenOptLevel::Aggressive));
        assert(Machine && "Unable to create Machine");
        FunctionType *Type = FunctionType::get(Type::getVoidTy(Ctx), false);
        assert(Type && "Unable to create Type");
        Function *F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test", &*Mod);
        assert(Type && "Unable to create Function");
        // auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test");
        // /own
        unsigned FunctionNum = 42;
        MMI = std::make_unique<MachineModuleInfo>(Machine.get());
        const TargetSubtargetInfo &STI = *Machine->getSubtargetImpl(*F);
        MF = std::make_unique<MachineFunction>(*F, *Machine, STI, MMI->getContext(), FunctionNum);
        TRI = MF->getSubtarget().getRegisterInfo();
        // copied from InstrRefLDVTest.cpp
        MaxReg = TRI->getNumSupportedRegs(*MF);
        MRI = TheTarget->createMCRegInfo(TargetTripleStr);
        assert(MRI && "Unable to create register info!");
        MCTargetOptions MCOptions;
        MAI = TheTarget->createMCAsmInfo(*MRI, TargetTripleStr, MCOptions);
        assert(MAI && "Unable to create asm info!");
        MCII = TheTarget->createMCInstrInfo();
        assert(MCII && "Unable to create MCInnstr info!");
        MSTI = TheTarget->createMCSubtargetInfo(TargetTripleStr, Cpu, "");
        assert(MSTI && "Unable to create MCSubtargetInfo!");
        Arch = MSTI->getTargetTriple().getArch(); // for convenience
        // set syntaxVariant here
        if (Arch == Triple::ArchType::x86_64)
            MIP = TheTarget->createMCInstPrinter(Triple(TargetTripleStr), 1, *MAI, *MCII, *MRI);
        else
            MIP = TheTarget->createMCInstPrinter(Triple(TargetTripleStr), 1, *MAI, *MCII, *MRI);
        assert(MIP && "Unable to create MCInstPrinter!");
        return SUCCESS;
    }

    // generates a latency benchmark for the instruction with Opcode. Generates
    // TargetInstrCount instructions.
    // If a InterleaveInst is provided it gets inserted after each generated instruction
    // UsedRegisters has to contain all registers used by the InterleaveInst
    // TargetInstructionCount will still be set to the number of generated instructions only
    // returns an error code, the generated assembly code and the opcode of the interleave
    // instruction if generated, -1 otherwise
    std::tuple<ErrorCode, AssemblyFile, int>
    genLatBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                    std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
                        *HelperInstructions,
                    std::set<MCRegister> UsedRegisters = {}) {
        dbg(__func__, "generating latency benchmark for ", MCII->getName(Opcode).data());
        // std::string result;
        // llvm::raw_string_ostream rso(result);
        auto benchTemplate = getTemplate(MSTI->getTargetTriple().getArch());
        // extract list of registers used by the template
        // TODO optimize
        for (unsigned i = 0; i < MRI->getNumRegs(); i++) {
            MCRegister reg = MCRegister::from(i);
            if (benchTemplate.usedRegisters.find(TRI->getRegAsmName(reg).lower().data()) !=
                benchTemplate.usedRegisters.end())
                UsedRegisters.insert(reg);
        }

        ErrorCode EC;
        MCInst interleaveInst;
        bool useInterleave = false;
        MCInst measureInst;
        // determine which regs the instruction can read and write including implicit ones like
        // FLAGS
        auto reads = getPossibleReadRegs(Opcode);
        auto writes = getPossibleWriteRegs(Opcode);

        // remove used registers from reads and writes
        reads = regDifference(reads, UsedRegisters);
        writes = regDifference(writes, UsedRegisters);
        // to generate a latency chain the instruction has to read and write to the same register
        std::set<MCRegister> common = regIntersect(reads, writes);

        if (common.empty()) {
            dbg(__func__, "detected no common registers, need helper");
            // cannot generate a latency chain on its own, find helper instruction
            // search the helperInstructions map for an instruction with opposite reads and writes
            for (auto [helperOpcode, helperReadRegs, helperWriteRegs] : *HelperInstructions) {
                // for a register written by the instruction we need a helper instruction that reads
                // it and vice versa
                auto fittingHelperReadRegs = regIntersect(helperReadRegs, writes);
                auto fittingHelperWriteRegs = regIntersect(helperWriteRegs, reads);

                if (!fittingHelperReadRegs.empty() && !fittingHelperWriteRegs.empty()) {
                    // found a helper instruction
                    dbg(__func__, "found helper instruction ", MCII->getName(Opcode).data());
                    MCRegister helperReadReg = *fittingHelperReadRegs.begin();
                    MCRegister helperWriteReg = *fittingHelperWriteRegs.begin();
                    std::tie(EC, measureInst) =
                        genInst(Opcode, UsedRegisters, false, helperWriteReg, helperReadReg);
                    if (EC != SUCCESS) return {EC, AssemblyFile(), -1};
                    std::tie(EC, interleaveInst) =
                        genInst(helperOpcode, UsedRegisters, false, helperReadReg, helperWriteReg);
                    // we should always be able to generate the helper instruction
                    if (EC != SUCCESS) return {ERROR_UNREACHABLE, AssemblyFile(), -1};
                    useInterleave = true;
                    // std::cout << MCII->getName(Opcode).data() << " using helper instruction "
                    //           << MCII->getName(helperOpcode).data() << "\n"
                    //           << std::flush;
                    break;
                }
            }
            if (!useInterleave) return {ERROR_NO_HELPER, AssemblyFile(), -1};
        } else {
            dbg(__func__, "detected common registers");
            // default behavior
            std::tie(EC, measureInst) = genInst(Opcode, UsedRegisters, true);
            if (EC != SUCCESS) return {EC, AssemblyFile(), -1};
        }

        // save registers used (genTPInnerLoop updates usedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : UsedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
                // generate code to save and restore register
                // this currently also saves registers already saved in the template
                // which is redundant but not harmful
                dbg(__func__, "generating save/restore code");
                auto [EC1, save] = genSaveRegister(reg);
                if (EC1 != SUCCESS) return {EC1, AssemblyFile(), -1};
                saveRegs.append(save);
                auto [EC2, restore] = genRestoreRegister(reg);
                if (EC2 != SUCCESS) return {EC2, AssemblyFile(), -1};
                restoreRegs.insert(0, restore);
            }
        }

        std::string loopCode;
        llvm::raw_string_ostream lco(loopCode);
        for (unsigned i = 0; i < *TargetInstrCount; ++i) {
            MIP->printInst(&measureInst, 0, "", *MSTI, lco);
            lco << "\n";
            if (useInterleave) {
                MIP->printInst(&interleaveInst, 0, "", *MSTI, lco);
                lco << "\n";
            }
        }
        std::string initCode;
        llvm::raw_string_ostream ico(initCode);
        MIP->printInst(&measureInst, 0, "", *MSTI, ico);
        ico << "\n";
        if (useInterleave) {
            MIP->printInst(&interleaveInst, 0, "", *MSTI, ico);
            ico << "\n";
        }

        AssemblyFile assemblyFile(Arch);
        assemblyFile.addInitFunction("init", initCode);
        assemblyFile.addBenchFunction("latency", saveRegs, loopCode, restoreRegs, "init");
        assemblyFile.addBenchFunction("latencyUnrolled", saveRegs, loopCode + loopCode, restoreRegs,
                                      "init");
        if (useInterleave) return {SUCCESS, assemblyFile, interleaveInst.getOpcode()};
        return {SUCCESS, assemblyFile, -1};
    }

    // generates a throughput benchmark for the instruction with Opcode. Tries to generate
    // TargetInstrCount different instructions and then unrolls them by UnrollCount. Updates
    // TargetInstrCount to the actual number of instructions in the loop (unrolls included)
    // If a InterleaveInst is provided it gets inserted after each generated instruction
    // UsedRegisters has to contain all registers used by the InterleaveInst
    // TargetInstructionCount will still be set to the number of generated instructions only
    std::pair<ErrorCode, AssemblyFile> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                      unsigned UnrollCount,
                                                      std::string InterleaveInst = "",
                                                      std::set<MCRegister> UsedRegisters = {}) {

        auto benchTemplate = getTemplate(MSTI->getTargetTriple().getArch());
        // extract list of registers used by the template
        // TODO optimize
        for (unsigned i = 0; i < MRI->getNumRegs(); i++) {
            MCRegister reg = MCRegister::from(i);
            if (benchTemplate.usedRegisters.find(TRI->getRegAsmName(reg).lower().data()) !=
                benchTemplate.usedRegisters.end())
                UsedRegisters.insert(reg);
        }

        auto [EC, instructions] = genTPInnerLoop(Opcode, *TargetInstrCount, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        dbg(__func__, "inner loop generated");

        // save registers used (genTPInnerLoop updates usedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : UsedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
                // generate code to save and restore register
                // this currently also saves registers already saved in the template
                // which is redundant but not harmful
                dbg(__func__, "calling genSave");
                auto [EC1, save] = genSaveRegister(reg);
                if (EC1 != SUCCESS) return {EC1, AssemblyFile()};
                saveRegs.append(save);
                dbg(__func__, "calling genRestore");
                auto [EC2, restore] = genRestoreRegister(reg);
                if (EC2 != SUCCESS) return {EC2, AssemblyFile()};
                restoreRegs.insert(0, restore);
            }
        }
        // update TargetInstructionCount to actual number of instructions generated
        *TargetInstrCount = instructions.size() * UnrollCount;
        dbg(__func__, "starting to build");

        std::string singleLoopCode;
        llvm::raw_string_ostream slo(singleLoopCode);
        for (auto inst : instructions) {
            MIP->printInst(&inst, 0, "", *MSTI, slo);
            slo << "\n";
            if (!InterleaveInst.empty()) slo << InterleaveInst << "\n";
        }
        std::string loopCode;
        for (unsigned i = 0; i < UnrollCount; i++)
            loopCode.append(singleLoopCode);

        AssemblyFile assemblyFile(Arch);
        assemblyFile.addInitFunction("init", singleLoopCode);
        assemblyFile.addBenchFunction("tp", saveRegs, loopCode, restoreRegs, "init");
        assemblyFile.addBenchFunction("tpUnroll2", saveRegs, loopCode + loopCode, restoreRegs,
                                      "init");
        assemblyFile.addBenchFunction(
            "tpUnroll4", saveRegs, loopCode + loopCode + loopCode + loopCode, restoreRegs, "init");
        return {SUCCESS, assemblyFile};
    }
    // generates a benchmark with TargetInstrCount1 times the instruction with Opcode1 and
    // TargetInstrCount2 times the instruction with Opcode2 and then unrolls them by UnrollCount.
    // Fails if not not enough registers were available to generate the requested number of
    // instructions.
    std::pair<ErrorCode, AssemblyFile> genOverlapBenchmark(unsigned Opcode1, unsigned Opcode2,
                                                           unsigned TargetInstrCount1,
                                                           unsigned TargetInstrCount2,
                                                           unsigned UnrollCount,
                                                           std::string FixedInstr2 = "") {
        std::set<MCRegister> UsedRegisters = {};
        auto benchTemplate = getTemplate(MSTI->getTargetTriple().getArch());
        // extract list of registers used by the template
        // TODO optimize
        for (unsigned i = 0; i < MRI->getNumRegs(); i++) {
            MCRegister reg = MCRegister::from(i);
            if (benchTemplate.usedRegisters.find(TRI->getRegAsmName(reg).lower().data()) !=
                benchTemplate.usedRegisters.end())
                UsedRegisters.insert(reg);
        }

        // auto [EC, instruction1] = genInst(Opcode1, UsedRegisters);
        // if (EC != SUCCESS) return {EC, ""};
        // auto [EC2, instruction2] = genInst(Opcode2, UsedRegisters);
        // if (EC2 != SUCCESS) return {EC2, ""};
        unsigned innerInstCount1 = 12;
        // find a balance between the two instructions to distribute the registers evenly
        // this is not necessary if the second instruction is fixed

        while (!FixedInstr2.empty()) {
            auto usedRegs = UsedRegisters;
            auto [EC, instructions1] = genTPInnerLoop(Opcode1, innerInstCount1, usedRegs);

            auto [EC2, instructions2] = genTPInnerLoop(Opcode2, 12, usedRegs);
            if (instructions2.size() >= instructions1.size()) break;
            // outs() << "instructions1 " << instructions1.size() << "\n";
            // outs() << "instructions2 " << instructions2.size() << "\n";
            // too many registers used for the first instruction -> adjust
            innerInstCount1--;
        }
        auto [EC, instructionPool1] = genTPInnerLoop(Opcode1, innerInstCount1, UsedRegisters);
        if (EC != SUCCESS) return {EC, AssemblyFile()};
        auto [EC2, instructionPool2] = genTPInnerLoop(Opcode2, innerInstCount1, UsedRegisters);
        if (EC2 != SUCCESS) return {EC2, AssemblyFile()};
        // now both sets of instrucions are of near equal length
        //  check if the desired number of instructions was generated
        // if (totalTargetInstrCount != instructions1.size() + instructions2.size())
        //     return {ERROR_GENERIC, ""};

        // save registers used (genTPInnerLoop updates UsedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : UsedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
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
        // update TargetInstructionCount to actual number of instructions generated
        // *TargetInstrCount1 = instructions.size() * UnrollCount;

        // unsigned totalTargetInstrCount = TargetInstrCount1 + TargetInstrCount2;

        std::string loopCode;
        llvm::raw_string_ostream lco(loopCode);
        auto iter1 = instructionPool1.begin();
        auto iter2 = instructionPool2.begin();
        for (unsigned i = 0; i < UnrollCount; i++) {
            for (unsigned i = 0; i < TargetInstrCount1; i++) {
                MIP->printInst(&*iter1, 0, "", *MSTI, lco);
                lco << "\n";
                iter1++;
                // go to beginning once all instructions used
                if (iter1 == instructionPool1.end()) iter1 = instructionPool1.begin();
                // MIP->printInst(&inst, 0, "", *MSTI, outs());
                // outs() << "\n";
            }
            for (unsigned i = 0; i < TargetInstrCount2; i++) {
                if (FixedInstr2.empty()) {
                    MIP->printInst(&*iter2, 0, "", *MSTI, lco);
                    lco << "\n";
                    iter2++;
                    // go to beginning once all instructions used
                    if (iter2 == instructionPool2.end()) iter2 = instructionPool2.begin();
                    // MIP->printInst(&inst, 0, "", *MSTI, outs());
                    // outs() << "\n";
                } else {
                    lco << FixedInstr2 << "\n";
                }
            }
        }
        AssemblyFile assemblyFile(Arch);
        assemblyFile.addInitFunction("init", loopCode);
        assemblyFile.addBenchFunction("latency", saveRegs, loopCode, restoreRegs, "init");
        return {SUCCESS, assemblyFile};
    }

    // generates a benchmark loop to measure throughput of an instruction
    // tries to generate targetInstrCount independent instructions for the inner
    // loop might generate less instructions than targetInstrCount if there are
    // not enough registers updates usedRegisters
    std::pair<ErrorCode, std::list<MCInst>> genTPInnerLoop(unsigned Opcode,
                                                           unsigned TargetInstrCount,
                                                           std::set<MCRegister> &UsedRegisters) {
        std::list<MCInst> instructions;
        const MCInstrDesc &desc = MCII->get(Opcode);
        // TODO do this much earlier
        if (isValid(desc) != SUCCESS) return {isValid(desc), {}};
        // MSTI->getFeatureBits().test(X86::FeatureFMA); TODO
        // STI.hasFeature(X86::Is16Bit) maybe also works
        unsigned numOperands = desc.getNumOperands();
        // this is a copy of the first generated instruction, all other instructions will use the
        // same registers as this one if they are only read
        std::optional<MCInst> refInst;
        // the first numDefs operands are destination operands
        // outs() << "desc.getNumDefs() " << desc.getNumDefs() << "\n";
        for (unsigned i = 0; i < TargetInstrCount; ++i) {
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
                } else {
                    switch (opInfo.OperandType) {
                    case MCOI::OPERAND_REGISTER: {
                        dbg(__func__, "adding register");

                        // search for unused register and add it as operand
                        const MCRegisterClass &RegClass = MRI->getRegClass(opInfo.RegClass);
                        bool foundRegister = false;
                        for (MCRegister reg : RegClass) {
                            if ((Arch == Triple::ArchType::x86_64 && reg.id() == 58) ||
                                reg.id() >= MaxReg)
                                // TODO replace with check for arch and X86::RAX
                                // RIP register (58) is included in GR64 class which is a bug
                                // see X86RegisterInfo.td:586
                                continue;
                            // check if sub- or superregisters are in use
                            if (std::any_of(
                                    UsedRegisters.begin(), UsedRegisters.end(),
                                    [reg, this](MCRegister R) { return TRI->regsOverlap(reg, R); }))
                                continue;
                            // this operand is readonly, use the same registers as the reference
                            // instruction
                            if (j >= desc.getNumDefs() && refInst)
                                reg = refInst->getOperand(j).getReg();

                            inst.addOperand(MCOperand::createReg(reg));
                            UsedRegisters.insert(reg);
                            foundRegister = true;
                            break;
                        }
                        if (!foundRegister) {
                            // outs() << "all supported registers of this class are in use"
                            //        << "\n";
                            return {SUCCESS, instructions};
                        }
                        break;
                    }
                    case MCOI::OPERAND_IMMEDIATE:
                        inst.addOperand(MCOperand::createImm(42));
                        break;
                    case MCOI::OPERAND_MEMORY:
                        // errs() << "instructions accessing memory are not supported at this "
                        //           "time\n";
                        return {MEMORY_OPERAND, {}};
                    case MCOI::OPERAND_PCREL:
                        // errs() << "branches are not supported at this time\n";
                        return {PCREL_OPERAND, {}};
                        ;
                    default:
                        // errs() << "unknown operand type\n";
                        return {UNKNOWN_OPERAND, {}};
                        ;
                    }
                }
            }
            // assign first instruction generated as reference instruction
            if (!refInst) refInst = inst;

            instructions.push_back(inst);
        }
        return {SUCCESS, instructions};
    }

    /**
     * \brief Generate an instruction TODO debug with VADDSSZrr
     *
     * This function takes an opcode and generates a valid MCInst. By default it uses different
     * registers for each operand. This can be changed by setting RequireReadRegister,
     * RequireWriteRegister and EnforceRWDependency. In LLVM operands which are read are called
     * "uses" and operands which are written are called "defs".
     *
     * \param Opcode Opcode of the instruction.
     * \param UsedRegisters A blacklist of registers not to be used.
     * \param EnforceRWDependency If true, the same register will be used for one read operand and
     * one write operand. If not possible, no instruction will be generated.
     * \param RequireUseRegister This register will be used for exactly one operand read if
     * possible, overriding UsedRegisters and ReuseRegisters. If not possible, no instruction will
     * be generated.
     * \param RequireDefRegister This register will be used for exactly one operand written if
     * possible, overriding UsedRegisters and ReuseRegisters. If not possible, no instruction will
     * be generated.
     * \return ErrorCode and generated instruction.
     */
    std::pair<ErrorCode, MCInst> genInst(unsigned Opcode, std::set<MCRegister> &UsedRegisters,
                                         bool RequireRWDependency = false,
                                         MCRegister RequireUseRegister = -1,
                                         MCRegister RequireDefRegister = -1) {
        const MCInstrDesc &desc = MCII->get(Opcode);
        unsigned numOperands = desc.getNumOperands();
        std::set<MCRegister> localDefs;
        std::set<MCRegister> localUses;
        std::set<MCRegister> localUsedRegisters;
        std::set<MCRegister> localImplDefs(desc.implicit_defs().begin(),
                                           desc.implicit_defs().end());
        std::set<MCRegister> localImplUses(desc.implicit_uses().begin(),
                                           desc.implicit_uses().end());
        std::set<MCRegister> localImplUsedRegisters;
        // keep track of requirements, first check if they get satisfied by implicit uses/defs
        bool satisfiedDefReq = localImplDefs.find(RequireDefRegister) != localImplDefs.end();
        bool satisfiedUseReq = localImplUses.find(RequireUseRegister) != localImplUses.end();
        bool satisfiedRWReq = !regIntersect(localImplDefs, localImplUses).empty();

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
                    if (j < desc.getNumDefs())
                        localDefs.insert(reg);
                    else
                        localUses.insert(reg);
                    dbg(__func__, "using tied register: ", TRI->getName(reg));
                }
            } else {
                switch (opInfo.OperandType) {
                case MCOI::OPERAND_REGISTER: {

                    // check if required reg can be used
                    const MCRegisterClass &RegClass = MRI->getRegClass(opInfo.RegClass);
                    if (!satisfiedUseReq && RequireUseRegister != -1 && j >= desc.getNumDefs() &&
                        regInRegClass(RequireUseRegister, RegClass)) {
                        inst.addOperand(MCOperand::createReg(RequireUseRegister));
                        localUses.insert(RequireUseRegister);
                        dbg(__func__,
                            "using register to satisfy use: ", TRI->getName(RequireUseRegister));
                        break;
                    }
                    if (!satisfiedDefReq && RequireDefRegister != -1 && j < desc.getNumDefs() &&
                        regInRegClass(RequireDefRegister, RegClass)) {
                        inst.addOperand(MCOperand::createReg(RequireDefRegister));
                        localDefs.insert(RequireDefRegister);
                        dbg(__func__,
                            "using register to satisfy def: ", TRI->getName(RequireDefRegister));
                        break;
                    }
                    // search for unused register and add it as this operand
                    bool foundRegister = false;
                    for (MCRegister reg : RegClass) {
                        if ((Arch == Triple::ArchType::x86_64 && reg.id() == 58) ||
                            reg.id() >= MaxReg)
                            // TODO replace with check for arch and X86::RAX
                            // RIP register (58) is included in GR64 class which is a bug
                            // see X86RegisterInfo.td:586
                            continue;
                        // dont use this if sub- or superregisters are in usedRegisters
                        if (std::any_of(
                                UsedRegisters.begin(), UsedRegisters.end(),
                                [reg, this](MCRegister R) { return TRI->regsOverlap(reg, R); }))
                            continue;
                        if (RequireRWDependency && !satisfiedRWReq && j >= desc.getNumDefs() &&
                            localDefs.find(reg) != localDefs.end()) {
                            // we need a rw dependency, it is not satisfied yet, we are defining the
                            // read operands right now so all writes are already definded and this
                            // register was already defined as write operand earlier
                            // -> use this as read operand to satisfy the dependency requirement
                            inst.addOperand(MCOperand::createReg(reg));
                            localUses.insert(reg);
                            dbg(__func__, "using register to satisfy RW: ", TRI->getName(reg));
                            foundRegister = true;
                            break;
                        }
                        // none of the special cases apply, default behavior applies: dont reuse any
                        // registers
                        if (std::any_of(
                                localUsedRegisters.begin(), localUsedRegisters.end(),
                                [reg, this](MCRegister R) { return TRI->regsOverlap(reg, R); }))
                            continue;

                        inst.addOperand(MCOperand::createReg(reg));
                        if (j < desc.getNumDefs())
                            localDefs.insert(reg);
                        else
                            localUses.insert(reg);
                        dbg(__func__, "using register: ", TRI->getName(reg));
                        foundRegister = true;
                        break;
                    }
                    if (!foundRegister) return {ERROR_NO_REGISTERS, {}};

                    break;
                }
                case MCOI::OPERAND_IMMEDIATE:
                    inst.addOperand(MCOperand::createImm(42));
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
            // update requirements
            satisfiedUseReq |= localUses.find(RequireUseRegister) != localUses.end();
            satisfiedDefReq |= localDefs.find(RequireDefRegister) != localDefs.end();
            satisfiedRWReq |= !regIntersect(localDefs, localUses).empty();
            localUsedRegisters = regUnion(localDefs, localUses);
        }
        if (RequireUseRegister != -1 && !satisfiedUseReq) {
            dbg(__func__, MCII->getName(Opcode).data(), " could not satisfy use ",
                TRI->getName(RequireUseRegister));
            return {ERROR_GEN_REQUIREMENT, {}};
        }
        if (RequireDefRegister != -1 && !satisfiedDefReq) {
            dbg(__func__, MCII->getName(Opcode).data(), " could not satisfy def ",
                TRI->getName(RequireDefRegister));
            return {ERROR_GEN_REQUIREMENT, {}};
        }
        if (RequireRWDependency && !satisfiedRWReq) {
            dbg(__func__, MCII->getName(Opcode).data(), " could not satisfy rw dependency ");
            return {ERROR_GEN_REQUIREMENT, {}};
        }
        UsedRegisters.insert(localUsedRegisters.begin(), localUsedRegisters.end());
        return {SUCCESS, inst};
    }

    std::pair<ErrorCode, MCRegister> getSupermostRegister(MCRegister Reg) {

        for (unsigned i = 0; i < 100; i++) {
            if (TRI->superregs(Reg).empty()) return {SUCCESS, Reg};
            Reg = *TRI->superregs(Reg).begin(); // take first superreg
        }
        return {ERROR_UNREACHABLE, NULL};
    }

    // TODO find ISA independent function in llvm
    std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg) {
        ErrorCode EC;
        // we dont want to save sub registers
        std::tie(EC, Reg) = getSupermostRegister(Reg);
        if (EC != SUCCESS) return {EC, ""};
        std::string result;
        llvm::raw_string_ostream rso(result); // Wrap with raw_ostream

        switch (Arch) {
        case llvm::Triple::x86_64: {
            MCInst inst;
            inst.setOpcode(getOpcode("PUSH64r"));
            inst.clear();
            inst.addOperand(MCOperand::createReg(Reg));
            MIP->printInst(&inst, 0, "", *MSTI, rso);
            rso << "\n";
            break;
        }
        case llvm::Triple::aarch64:
            return {SUCCESS, ""}; // all registers saved in template
        default:
            return {ERROR_UNSUPPORTED_ARCH, ""};
        }

        return {SUCCESS, result};
    }

    // TODO find ISA independent function in llvm
    std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg) {
        ErrorCode EC;
        std::tie(EC, Reg) = getSupermostRegister(Reg);
        if (EC != SUCCESS) return {EC, ""};
        std::string result;
        llvm::raw_string_ostream rso(result);

        switch (Arch) {
        case llvm::Triple::x86_64: {
            MCInst inst;
            inst.setOpcode(getOpcode("POP64r"));
            inst.clear();
            inst.addOperand(MCOperand::createReg(Reg));
            MIP->printInst(&inst, 0, "", *MSTI, rso);
            rso << "\n";
            break;
        }
        case llvm::Triple::aarch64:
            return {SUCCESS, ""}; // all registers restored in template
        default:
            return {ERROR_UNSUPPORTED_ARCH, ""};
        }
        return {SUCCESS, result};
    }

    bool regInRegClass(MCRegister Reg, MCRegisterClass RegClass) {
        for (MCRegister reg : RegClass)
            if (reg == Reg) return true;
        return false;
    }

    // filter which instructions get exluded
    ErrorCode isValid(MCInstrDesc Desc) {
        if (Desc.isPseudo()) return PSEUDO_INSTRUCTION;
        if (Desc.mayLoad()) return MAY_LOAD;
        if (Desc.mayStore()) return MAY_STORE;
        if (Desc.isCall()) return IS_CALL;
        if (Desc.isMetaInstruction()) return IS_META_INSTRUCTION;
        if (Desc.isReturn()) return IS_RETURN;
        if (Desc.isBranch()) return IS_BRANCH; // TODO uops has TP, how?
        // if (X86II::isPrefix(Instruction.TSFlags)) return INSTRUCION_PREFIX;
        // Two more checks which only work after generating an instruction TODO find other way
        std::set<MCRegister> emptySet;
        auto [EC, inst] = genInst(Desc.getOpcode(), emptySet);
        if (EC != SUCCESS) return EC;
        std::string temp;
        llvm::raw_string_ostream tso(temp);
        MIP->printInst(&inst, 0, "", *MSTI, tso);
        // this is very ugly, these # instructions have isCodeGenOnly flag, how can
        // we check it?
        if (temp.find("#") != std::string::npos) return IS_CODE_GEN_ONLY;

        // some pseudo instructions are not marked as pseudo (ABS_Fp32)
        if (temp.find_first_not_of('\t') == std::string::npos) return DOES_NOT_EMIT_INST;
        return SUCCESS;
    }

    // get Opcode for instruction
    // TODO there probably is a mechanism for this in llvm -> find and use
    unsigned getOpcode(std::string InstructionName) {
        for (unsigned i = 0; i < MCII->getNumOpcodes(); ++i) {
            if (MCII->getName(i) == InstructionName) {
                return i;
            }
        }
        errs() << "Instruction not found: " << InstructionName << "\n";
        return 1;
    }

    /**
    get all registers which can be read by an instruction including implicit uses
    */
    std::set<MCRegister> getPossibleReadRegs(unsigned Opcode) {
        std::set<MCRegister> reads;
        const MCInstrDesc &desc = MCII->get(Opcode);
        for (unsigned i = desc.getNumDefs(); i < desc.getNumOperands(); i++) {
            if (desc.operands()[i].OperandType != MCOI::OPERAND_REGISTER) continue;
            auto regClass = MRI->getRegClass(desc.operands()[i].RegClass);
            for (auto reg : regClass) {
                reads.insert(reg);
            }
        }
        for (auto reg : desc.implicit_uses()) {
            reads.insert(MCRegister::from(reg));
        }
        return reads;
    }

    /**
    get all registers which can be written by an instruction including implicit defs
    */
    std::set<MCRegister> getPossibleWriteRegs(unsigned Opcode) {
        std::set<MCRegister> writes;
        const MCInstrDesc &desc = MCII->get(Opcode);
        for (unsigned i = 0; i < desc.getNumDefs(); i++) {
            if (desc.operands()[i].OperandType != MCOI::OPERAND_REGISTER) continue;
            auto regClass = MRI->getRegClass(desc.operands()[i].RegClass);
            for (auto reg : regClass) {
                writes.insert(reg);
            }
        }
        for (auto reg : desc.implicit_defs()) {
            writes.insert(MCRegister::from(reg));
        }
        return writes;
    }

    std::set<MCRegister> regIntersect(std::set<MCRegister> A, std::set<MCRegister> B) {
        std::set<MCRegister> result;
        std::set_intersection(A.begin(), A.end(), B.begin(), B.end(),
                              std::inserter(result, result.begin()));
        return result;
    }

    std::set<MCRegister> regDifference(std::set<MCRegister> A, std::set<MCRegister> B) {
        std::set<MCRegister> result;
        std::set_difference(A.begin(), A.end(), B.begin(), B.end(),
                            std::inserter(result, result.begin()));
        return result;
    }

    std::set<MCRegister> regUnion(std::set<MCRegister> A, std::set<MCRegister> B) {
        std::set<MCRegister> result;
        std::set_union(A.begin(), A.end(), B.begin(), B.end(),
                       std::inserter(result, result.begin()));
        return result;
    }
};
