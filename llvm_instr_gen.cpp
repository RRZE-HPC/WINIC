// #include
// "/mnt/c/Users/User/Desktop/Bachelor_Local/llvm-project/llvm/tools/llvm-mc/llvm-mc.cpp"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "templates.cpp"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
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
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>

// #include "llvm/lib/Target/X86/X86RegisterInfo.h"
// #include <llvm/include/llvm/ADT/StringRef.h>
// #include "llvm/MC/MCAsmInfo.h"
// #include "llvm/MC/MCTargetOptions.h"
// #include "llvm/MC/MCSubtargetInfo.h"
// #include "llvm/Support/raw_ostream.h"
// #include "llvm/MC/MCDisassembler/MCDisassembler.h"

/*
TODO
compile and run from inside llvm
implement loop instruction interference detection
move to clang for assembling to avoid gcc dependency
check filtering memory instructions
test other arches
add templates for other arches
-save callee saved registers
*/

// helpful
// TRI->getRegAsmName(MCRegister)

using namespace llvm;

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
        LLVMInitializeX86AsmParser();
        LLVMInitializeX86AsmPrinter();
        LLVMInitializeX86Disassembler();
        LLVMInitializeX86TargetMCA();

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
            Triple::normalize(TargetTripleStr), "ivybridge", "", Options, std::nullopt,
            std::nullopt, CodeGenOptLevel::Aggressive));

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

        MSTI = TheTarget->createMCSubtargetInfo(TargetTripleStr, "ivybridge", "");
        assert(MSTI && "Unable to create MCSubtargetInfo!");

        // set syntax variant here
        MIP = TheTarget->createMCInstPrinter(Triple(TargetTripleStr), 1, *MAI, *MCII, *MRI);
        assert(MIP && "Unable to create MCInstPrinter!");
    }

    int createAnyValidInstruction(unsigned Opcode) {
        const MCInstrDesc &desc = MCII->get(Opcode);
        if (!isValid(desc))
            return 1;
        unsigned numOperands = desc.getNumOperands();
        std::set<MCRegister> usedRegisters;

        MCInst tempInst;
        tempInst.setOpcode(Opcode);
        tempInst.clear();

        for (unsigned j = 0; j < numOperands; ++j) {
            const MCOperandInfo &opInfo = desc.operands()[j];

            // TIED_TO points to operand which this has to be identical to see
            // MCInstrDesc.h:41
            if (opInfo.Constraints & (1 << MCOI::TIED_TO)) {
                // this operand must be identical to another operand
                unsigned TiedToOp = (opInfo.Constraints >> (4 + MCOI::TIED_TO * 4)) & 0xF;
                tempInst.addOperand(tempInst.getOperand(TiedToOp));
                outs() << "added tied operand again: " << TiedToOp << "\n";
            } else {
                // search for unused register and add it as operand
                const MCRegisterClass &RegClass = MRI->getRegClass(opInfo.RegClass);
                for (MCRegister reg : RegClass) {
                    // outs() << "trying: " << Reg.id() << " name: " << TRI->getName(Reg)
                    // <<
                    // "\n";
                    if (reg.id() >= MaxReg) {
                        outs() << "all supported registers of this class are in use"
                               << "\n";
                        // TODO handle this case
                        break;
                    }
                    if (usedRegisters.find(reg) == usedRegisters.end()) {
                        tempInst.addOperand(MCOperand::createReg(reg));
                        usedRegisters.insert(reg);
                        break;
                    }
                }
            }
        }
        MIP->printInst(&tempInst, 0, "", *MSTI, outs());
        outs() << "\n";

        return 0;
    }

    std::string genTPBenchmark(unsigned Opcode, unsigned TargetInstrCount) {
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
        if (benchTemplate.usedRegisters.size() != usedRegisters.size())
            return ""; // probably error in template

        std::list<MCInst> instructions = genTPInnerLoop(Opcode, TargetInstrCount, usedRegisters);

        // save registers used (genTPInnerLoop updates usedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : usedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
                // generate code to save and restore register
                // this currently also saves registers already saved in the template
                // which is redundant but not harmful
                saveRegs.append(genSaveRegister(reg)).append("\n");
                restoreRegs.insert(0, genRestoreRegister(reg).append("\n"));
            }
        }
        rso << "#define NINST " << instructions.size() << "\n";
        rso << benchTemplate.preLoop;
        rso << saveRegs;

        // init registers (just repeat loop)
        for (auto inst : instructions) {
            MIP->printInst(&inst, 0, "", *MSTI, rso);
            rso << "\n";
        }
        rso << benchTemplate.beginLoop;
        for (auto inst : instructions) {
            MIP->printInst(&inst, 0, "", *MSTI, rso);
            rso << "\n";
        }

        rso << benchTemplate.midLoop;
        rso << benchTemplate.endLoop;
        rso << restoreRegs;
        rso << benchTemplate.postLoop << "\n";
        return result;
    }

    // generates a benchmark loop to measure throughput of an instruction
    // tries to generate targetInstrCount independent instructions for the inner
    // loop might generate less instructions than targetInstrCount if there are
    // not enough registers updates usedRegisters
    std::list<MCInst> genTPInnerLoop(unsigned Opcode, unsigned TargetInstrCount,
                                     std::set<MCRegister> &UsedRegisters) {
        std::list<MCInst> instructions;
        const MCInstrDesc &desc = MCII->get(Opcode);
        if (!isValid(desc))
            return {};
        unsigned numOperands = desc.getNumOperands();

        // the first numDefs operands are destination operands
        // outs() << "desc.getNumDefs() " << desc.getNumDefs() << "\n";

        for (unsigned i = 0; i < TargetInstrCount; ++i) {
            MCInst inst;
            inst.setOpcode(Opcode);
            inst.clear();

            for (unsigned j = 0; j < numOperands; ++j) {
                const MCOperandInfo &opInfo = desc.operands()[j];

                // TIED_TO points to operand which this has to be identical to. see
                // MCInstrDesc.h:41
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
                            outs() << "all supported registers of this class are in use"
                                   << "\n";
                            // TODO handle this case properly
                            return instructions;
                        }
                        break;
                    }
                    case MCOI::OPERAND_IMMEDIATE:
                        inst.addOperand(MCOperand::createImm(42));
                        break;
                    case MCOI::OPERAND_MEMORY:
                        errs() << "instructions accessing memory are not supported at this "
                                  "time";
                        return {};
                    case MCOI::OPERAND_PCREL:
                        errs() << "branches are not supported at this time";
                        return {};
                    default:
                        errs() << "unknown operand type";
                        return {};
                    }
                }
            }
            instructions.push_back(inst);
        }
        return instructions;
    }

    // TODO find ISA independent function in llvm
    std::string genSaveRegister(MCRegister Reg) {
        MCInst inst;
        inst.setOpcode(getOpcode("PUSH64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        std::string result;
        llvm::raw_string_ostream rso(result); // Wrap the string with raw_ostream
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return result;
    }

    // TODO find ISA independent function in llvm
    std::string genRestoreRegister(MCRegister Reg) {
        MCInst inst;
        inst.setOpcode(getOpcode("POP64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        std::string result;
        llvm::raw_string_ostream rso(result);
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return result;
    }

    // filter which instructions get exluded
    bool isValid(MCInstrDesc Instruction) {
        return !Instruction.isPseudo() && !Instruction.mayLoad() && !Instruction.mayStore();
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

double benchmark(std::string Assembly, int N) {
    std::string sPath = "/dev/shm/temp.s";
    std::string oPath = "/dev/shm/temp.so";
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return 1;
    }
    asmFile << Assembly;
    asmFile.close();
    // std::string command = "llvm-mc --mcpu=ivybridge --filetype=obj " + s_path
    // + " -o " + o_path;
    std::string command = "gcc -x assembler-with-cpp -shared " + sPath + " -o " + oPath;
    system(command.data());

    // from ibench
    void *handle;
    double (*latency)(int);
    int *ninst;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .o file\n");
        exit(EXIT_FAILURE);
    }
    if ((latency = (double (*)(int))dlsym(handle, "latency")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find function latency\n");
        return (EXIT_FAILURE);
    }
    if ((ninst = (int *)dlsym(handle, "ninst")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find symbol ninst\n");
        return (EXIT_FAILURE);
    }

    struct timeval start, end;
    double benchtime;

    gettimeofday(&start, NULL);
    (*latency)(N);
    gettimeofday(&end, NULL);
    benchtime = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
    // printf("%.3f (benchtime)\n",  benchtime);
    return benchtime;
}

int main(int argc, char **argv) {
    double n = 1e6;
    if (argc < 2) {
        errs() << "Usage: " << argv[0] << " <instruction_name>" << " [numInstructions]"
               << " [frequency (GHz)]\n";
        return 1;
    }

    int numInst = 6;
    if (argc == 3) {
        numInst = atoi(argv[2]);
    }
    double freq = 3.75;
    if (argc == 4) {
        freq = atof(argv[3]);
    }

    auto generator = BenchmarkGenerator();
    generator.setUp();
    StringRef instrName(argv[1]);
    unsigned opcode = generator.getOpcode(instrName.data());
    std::string result;
    llvm::raw_string_ostream rso(result);
    std::string assembly = generator.genTPBenchmark(opcode, numInst);
    double time = benchmark(assembly, n);
    double tp = time / (1e6 * numInst / freq * (n / 1e9));
    // outs() << time << "\n";
    std::printf("%.3f clock cycles\n", tp);
    return 0;
}

// outs() << TRI->getNumSupportedRegs(*MF) << "\n";
// const X86Subtarget &ST = MF->getSubtarget<X86Subtarget>();
// const X86RegisterInfo *RegInfo = ST.getRegisterInfo();
// outs() << RegInfo->getNumSupportedRegs(*MF) << "\n";
// outs() << "RegInfo->getNumRegs()" << RegInfo->getNumRegs() << "\n";

// variant put loop increment in mid of instructions
// stream() << benchTemplate.preLoop;
// stream() << benchTemplate.beginLoop;
// unsigned halfSize = instructions.size() / 2;
// auto it = instructions.begin();
// for (unsigned i; i < instructions.size(); i++) {
//     MCInst inst = *it;
//     MIP->printInst(&inst, 0, "", *MSTI, stream());
//     stream() << "\n";
//     if (i == halfSize - 1)
//         stream() << benchTemplate.midLoop;
//     it++;
// }
