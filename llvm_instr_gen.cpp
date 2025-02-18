// #include
// "/mnt/c/Users/User/Desktop/Bachelor_Local/llvm-project/llvm/tools/llvm-mc/llvm-mc.cpp"
#include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "templates.cpp"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
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
#include "llvm/Support/Error.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/TargetParser/X86TargetParser.h"
#include <algorithm>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <list>
#include <math.h>
#include <memory>
#include <set>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <variant>

// #include "llvm/Support/FileSystem.h"
// #include "llvm/MC/MCObjectWriter.h"
// #include "llvm/CodeGen/MachineRegisterInfo.h"
// #include "llvm/lib/Target/X86/X86RegisterInfo.h"
// #include <llvm/include/llvm/ADT/StringRef.h>
// #include "llvm/MC/MCAsmInfo.h"
// #include "llvm/MC/MCTargetOptions.h"
// #include "llvm/MC/MCSubtargetInfo.h"
// #include "llvm/Support/raw_ostream.h"
// #include "llvm/MC/MCDisassembler/MCDisassembler.h"

/*
TODO
replace generic errors
MCInstrPrinter segfaults when instruction is wrong (or is Prefix)
move to clang for assembling to avoid gcc dependency
test other arches
add templates for other arches
init registers (e.g. avoid avx-sse transition penalty)

-check filtering memory instructions
-implement loop instruction interference detection
-compile and run from inside program
-save callee saved registers

Fragen:
compilation time

*/

// helpful
// TRI->getRegAsmName(MCRegister)

using namespace llvm;
// using namespace X86;

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
    TEMPLATE_ERROR,
    ASSEMBLY_ERROR,
    GENERIC_ERROR,
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
    case TEMPLATE_ERROR:
        return "TEMPLATE_ERROR";
    case ASSEMBLY_ERROR:
        return "ASSEMBLY_ERROR";
    case GENERIC_ERROR:
        return "GENERIC_ERROR";
    }
}

class BenchmarkGenerator {
  public:
    LLVMContext Ctx;
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

    BenchmarkGenerator() : Ctx(), Mod(std::make_unique<Module>("beehives", Ctx)) {}

    void setUp() {
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmPrinter();
        // LLVMInitializeX86AsmParser();
        // LLVMInitializeX86Disassembler();
        // LLVMInitializeX86TargetMCA();

        StringRef TargetTripleStr = "x86_64-pc-linux";
        // StringRef TargetTripleStr = "x86_64--";

        // copied from InstrRefLDVTest.cpp
        Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
                           "f80:128-n8:16:32:64-S128");
        Triple TargetTriple(TargetTripleStr);
        std::string Error;
        const Target *TheTarget = TargetRegistry::lookupTarget("", TargetTriple, Error);

        TargetOptions Options;
        Machine = std::unique_ptr<TargetMachine>(TheTarget->createTargetMachine(
            Triple::normalize(TargetTripleStr), "znver4", "", Options, std::nullopt, std::nullopt,
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

        MSTI = TheTarget->createMCSubtargetInfo(TargetTripleStr, "znver4", "");
        assert(MSTI && "Unable to create MCSubtargetInfo!");

        // set syntax variant here
        MIP = TheTarget->createMCInstPrinter(Triple(TargetTripleStr), 1, *MAI, *MCII, *MRI);
        assert(MIP && "Unable to create MCInstPrinter!");
    }

    // generates a throughput benchmark for the instruction with Opcode. Tries to generate
    // TargetInstrCount different instructions and ten unrolls them by UnrollCount. Updates
    // TargetInstrCount to the actual number of instructions in the loop (unrolls included)
    std::pair<ErrorCode, std::string> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                     unsigned UnrollCount) {
        std::string result;
        llvm::raw_string_ostream rso(result);
        auto benchTemplate = x86Template();
        // extract list of registers used by the template
        std::set<MCRegister> usedRegisters;
        for (unsigned i = 0; i < MRI->getNumRegs(); i++) {
            MCRegister reg = MCRegister::from(i);

            if (benchTemplate.usedRegisters.find(TRI->getRegAsmName(reg).lower().data()) !=
                benchTemplate.usedRegisters.end())
                usedRegisters.insert(reg);
        }
        if (benchTemplate.usedRegisters.size() != usedRegisters.size()) {
            errs() << "could not determine all registers used by the template\n";
            return {TEMPLATE_ERROR, ""}; // probably error in template TODO error type
        }

        auto [EC, instructions] = genTPInnerLoop(Opcode, *TargetInstrCount, usedRegisters);
        if (EC != SUCCESS) return {EC, ""};
        // update TargetInstructionCount to actual number of instructions generated
        *TargetInstrCount = instructions.size() * UnrollCount;

        // save registers used (genTPInnerLoop updates usedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : usedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
                // generate code to save and restore register
                // this currently also saves registers already saved in the template
                // which is redundant but not harmful
                auto [EC1, save] = genSaveRegister(reg);
                if (EC1 != SUCCESS) return {EC, ""};
                saveRegs.append(save).append("\n");

                auto [EC2, restore] = genRestoreRegister(reg);
                if (EC != SUCCESS) return {EC, ""};
                restoreRegs.insert(0, restore.append("\n"));
            }
        }
        rso << "#define NINST " << *TargetInstrCount << "\n";
        rso << benchTemplate.preLoop;
        rso << saveRegs;

        rso << benchTemplate.beginLoop;
        for (unsigned i = 0; i < UnrollCount; i++) {
            for (auto inst : instructions) {
                // TODO this is very ugly, these # instructions have isCodeGenOnly flag, how can we check it?
                // if found, add check to isValid()
                std::string temp;
                llvm::raw_string_ostream tso(temp);
                MIP->printInst(&inst, 0, "", *MSTI, tso);
                if (temp.find("#") != std::string::npos) return {IS_CODE_GEN_ONLY, ""};

                MIP->printInst(&inst, 0, "", *MSTI, rso);
                rso << "\n";
            }
        }

        rso << benchTemplate.midLoop;
        rso << benchTemplate.endLoop;

        rso << restoreRegs;
        rso << benchTemplate.postLoop << "\n";
        return {SUCCESS, result};
    }

    void temp(unsigned Opcode) {
        const MCInstrDesc &desc = MCII->get(Opcode);
        if (desc.TSFlags & X86::FEATURE_64BIT) outs() << "FEATURE_64BIT bit\n";
        if (desc.TSFlags & X86::FeatureSSE2) outs() << "FeatureSSE2 bit\n";
        if (desc.TSFlags & X86II::PrefixByte) outs() << "PrefixByte bit\n";
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
        if (isValid(desc) != SUCCESS) return {isValid(desc), {}};
        // MSTI->getFeatureBits().test(X86::FeatureFMA); TODO
        // STI.hasFeature(X86::Is16Bit) maybe also works

        unsigned numOperands = desc.getNumOperands();

        // the first numDefs operands are destination operands
        // outs() << "desc.getNumDefs() " << desc.getNumDefs() << "\n";

        for (unsigned i = 0; i < TargetInstrCount; ++i) {
            MCInst inst;
            inst.setOpcode(Opcode);
            inst.clear();

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
                        // search for unused register and add it as operand
                        const MCRegisterClass &RegClass = MRI->getRegClass(opInfo.RegClass);
                        bool foundRegister = false;
                        for (MCRegister reg : RegClass) {
                            if (reg.id() >= MaxReg || reg.id() == 58)
                                // RIP register (58) is included in GR64 class which is a bug
                                // see X86RegisterInfo.td:586
                                continue;

                            // check if sub or superregisters are in use
                            if (std::any_of(
                                    UsedRegisters.begin(), UsedRegisters.end(),
                                    [reg, this](MCRegister R) { return TRI->regsOverlap(reg, R); }))
                                continue;

                            inst.addOperand(MCOperand::createReg(reg));
                            UsedRegisters.insert(reg);
                            foundRegister = true;
                            break;
                        }
                        if (!foundRegister) {
                            // outs() << "all supported registers of this class are in use"
                            //        << "\n";
                            // TODO handle this case properly
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
            instructions.push_back(inst);
        }
        return {SUCCESS, instructions};
    }

    std::pair<ErrorCode, MCRegister> getSupermostRegister(MCRegister Reg) {
        std::list<MCRegister> superregs;
        for (auto reg : TRI->superregs(Reg))
            superregs.insert(superregs.begin(), reg);
        if (superregs.empty()) return {SUCCESS, Reg};

        for (unsigned i = 0; i < 10; i++) {
            if (superregs.size() == 1) break;

            auto r = superregs.front();
            superregs.pop_front();
            for (auto sr : TRI->superregs(r))
                if (std::find(superregs.begin(), superregs.end(), sr) == superregs.end())
                    superregs.insert(superregs.end(), sr);
        }
        // now only one superregister should be left
        if (superregs.size() == 1) return {SUCCESS, superregs.front()};

        return {GENERIC_ERROR, NULL};
    }

    // TODO find ISA independent function in llvm
    std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg) {
        ErrorCode EC;
        // we dont want to save sub registers
        std::tie(EC, Reg) = getSupermostRegister(Reg);
        if (EC != SUCCESS) return {EC, ""};

        MCInst inst;
        inst.setOpcode(getOpcode("PUSH64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        std::string result;
        llvm::raw_string_ostream rso(result); // Wrap the string with raw_ostream
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return {SUCCESS, result};
    }

    // TODO find ISA independent function in llvm
    std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg) {
        ErrorCode EC;
        std::tie(EC, Reg) = getSupermostRegister(Reg);
        if (EC != SUCCESS) return {EC, ""};

        MCInst inst;
        inst.setOpcode(getOpcode("POP64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        std::string result;
        llvm::raw_string_ostream rso(result);
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return {SUCCESS, result};
    }

    // filter which instructions get exluded
    ErrorCode isValid(MCInstrDesc Instruction) {
        if (Instruction.isPseudo()) return PSEUDO_INSTRUCTION;
        if (Instruction.mayLoad()) return MAY_LOAD;
        if (Instruction.mayStore()) return MAY_STORE;
        if (Instruction.isCall()) return IS_CALL;
        if (Instruction.isMetaInstruction()) return IS_META_INSTRUCTION;
        if (Instruction.isReturn()) return IS_RETURN;
        if (Instruction.isBranch()) return IS_BRANCH; // TODO uops has TP, how?
        if (X86II::isPrefix(Instruction.TSFlags)) return INSTRUCION_PREFIX;
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
};

static std::pair<ErrorCode, double> runBenchmark(std::string Assembly, int N) {
    std::string sPath = "/dev/shm/temp.s";
    std::string oPath = "/dev/shm/temp.so";
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return {GENERIC_ERROR, 1};
    }
    asmFile << Assembly;
    asmFile.close();
    // std::string command = "llvm-mc --mcpu=ivybridge --filetype=obj " + s_path
    // + " -o " + o_path;
    // gcc -x assembler-with-cpp -shared /dev/shm/temp.s -o /dev/shm/temp.so &> gcc_out"
    std::string command =
        "gcc -x assembler-with-cpp -shared " + sPath + " -o " + oPath + " 2> gcc_out";
    if (system(command.data()) != 0) return {ASSEMBLY_ERROR, 1};

    // from ibench
    void *handle;
    double (*latency)(int);
    int *ninst;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        return {GENERIC_ERROR, 1};
    }
    if ((latency = (double (*)(int))dlsym(handle, "latency")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find function latency\n");
        return {GENERIC_ERROR, 1};
    }
    if ((ninst = (int *)dlsym(handle, "ninst")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find symbol ninst\n");
        return {GENERIC_ERROR, 1};
    }

    struct timeval start, end;
    double benchtime;

    // prime function ? feels more reliable, TODO test
    outs() << "benchmarking now\n";
    (*latency)(N);
    gettimeofday(&start, NULL);
    (*latency)(N);
    gettimeofday(&end, NULL);
    benchtime = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
    // printf("%.3f (benchtime)\n",  benchtime);
    dlclose(handle);
    return {SUCCESS, benchtime};
}

// runs two benchmarks to correct eventual interference with loop instructions
static std::pair<ErrorCode, double>
measureThroughput(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
    unsigned numInst1 = 100;
    unsigned numInst2 = 100; // make the generator generate as many operations as possible

    double n = 1000000;
    std::string assembly;
    ErrorCode EC;
    double time_1;
    double time_2;
    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst1, 1);
    if (EC != SUCCESS) return {EC, 1};
    std::tie(EC, time_1) = runBenchmark(assembly, n);
    if (EC != SUCCESS) return {EC, 1};

    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst2, 2);
    if (EC != SUCCESS) return {EC, 1};
    std::tie(EC, time_2) = runBenchmark(assembly, n);
    if (EC != SUCCESS) return {EC, 1};

    // std::printf("time_1: %.3f \n", time_1);
    // std::printf("time_2: %.3f \n", time_2);

    // predict if loop instructions interfere with the execution
    // see README for explanation TODO
    double loopInstr = numInst1 * (time_2 - 2 * time_1) / (time_1 - time_2);

    int nLoopInstr = std::round(loopInstr);
    if (nLoopInstr >= 1)
        std::printf("debug: estimating %.3f instructions interfering with measurement\n",
                    loopInstr);
    // double uncorrected = time_1 / (1e6 * numInst1 / Frequency * (n / 1e9));
    double intCorrected = time_1 / (1e6 * (numInst1 + nLoopInstr) / Frequency * (n / 1e9));
    // double floatCorrected = time_1 / (1e6 * (numInst1 + loopInstr) / Frequency * (n / 1e9));

    // std::printf("%.3f uncorrected tp\n", uncorrected);
    // std::printf("%.3f intCorrected tp\n", intCorrected);
    // std::printf("%.3f floatCorrected tp\n", floatCorrected);

    return {SUCCESS, intCorrected};
}

static double simpleMeasurement(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency,
                                unsigned *NumInst, unsigned UnrollCount) {
    unsigned n = 1e6;
    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    auto [EC, assembly] = Generator->genTPBenchmark(Opcode, NumInst, UnrollCount);
    auto [EC2, time] = runBenchmark(assembly, n);
    double tp = time / (1e6 * *NumInst / Frequency * (n / 1e9));
    outs() << time << "\n";
    std::printf("%.3f clock cycles\n", tp);
    return 0;
}

static int buildDatabase(double Frequency) {
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();
    for (unsigned opcode = 0; opcode < generator.MCII->getNumOpcodes(); opcode++) {
        auto [EC, tp] = measureThroughput(opcode, &generator, Frequency);
        if (EC != SUCCESS) {
            std::string name = generator.MCII->getName(opcode).data();
            name.resize(15, ' ');
            outs() << name << ": " << "skipped for reason\t " << ecToString(EC) << "\n";
            continue;
        }
        // outs() << generator.MCII->getName(opcode) << ": " << tp << " (clock cycles)\n";
        std::printf("%s: %.3f (clock cycles)\n", generator.MCII->getName(opcode).data(), tp);
    }
    return 0;
}

int main(int argc, char **argv) {
    // if (argc < 2) {
    //     errs() << "Usage: " << argv[0] << " <instruction_name>" << " [numInstructions]"
    //            << " [unrollCount]" << " [frequency (GHz)]\n";
    //     return 1;
    // }

    StringRef instrName;
    if (argc >= 2) {
        instrName = argv[1];
    }
    unsigned numInst = 6;
    if (argc >= 3) {
        numInst = atoi(argv[2]);
    }
    unsigned unrollCount = 1;
    if (argc >= 4) {
        unrollCount = atof(argv[3]);
    }
    double frequency = 3.75;
    if (argc == 5) {
        frequency = atof(argv[4]);
    }

    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();

    if (argc == 1) buildDatabase(frequency);
    if (argc >= 2) {
        unsigned opcode = generator.getOpcode(instrName.data());
        generator.temp(opcode);
        // auto [EC, tp] = measureThroughput(opcode, &generator, frequency);
        // if (EC != SUCCESS)
        //     outs() << ecToString(EC) << "\n";
        // else
        //     std::printf("%.3f (clock cycles)\n", tp);
    }

    return 0;
}
