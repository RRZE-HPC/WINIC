#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

int main(int argc, char **argv) {
    if (argc < 2) {
        errs() << "Usage: " << argv[0] << " <instruction_name>\n";
        return 1;
    }
    InitializeAllTargets();

    StringRef TargetTriple = "x86_64-linux-gnu";
    std::string Error;
    const Target *TheTarget = TargetRegistry::lookupTarget(TargetTriple, Error);
    if (!TheTarget) {
        errs() << "Error: " << Error << "\n";
        return 1;
    }

    // Initialize components
    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
    InitializeAllAsmParsers();
    InitializeAllDisassemblers();

    auto MRI = TheTarget->createMCRegInfo(TargetTriple);
    MCTargetOptions MCOptions;
    auto MAI = TheTarget->createMCAsmInfo(*MRI, TargetTriple, llvm::MCTargetOptions());
    auto MII = TheTarget->createMCInstrInfo();
    // auto MOFI = TheTarget->createMCObjectFileInfo(); // New line
    auto MIP = TheTarget->createMCInstPrinter(Triple(TargetTriple), 0, *MAI, *MII, *MRI);
    
    llvm::TargetOptions options;
    TargetMachine *TM = TheTarget->createTargetMachine(TargetTriple, "generic", "", options, Reloc::PIC_); 
    // const MCSubtargetInfo &STI = TM->getSubtargetImpl();  // Get the MCSubtargetInfo
    auto STI = TheTarget->createMCSubtargetInfo(TargetTriple, "", "");
    // MCContext Ctx(MAI, MRI, MOFI, nullptr); // New line
    
    StringRef InstrName(argv[1]);
    for (unsigned i = 0; i < MII->getNumOpcodes(); ++i) {
        if (MII->getName(i) == InstrName) {
            MCInst Inst;
            Inst.setOpcode(i);

            // Add dummy operands (this depends on the instruction)
            // Inst.addOperand(MCOperand::createReg(0)); // Example operand, replace as needed
            // Inst.addOperand(MCOperand::createImm(0)); // Example operand, replace as needed
            
            // Print the instruction
            if (!STI){
                errs() << "Error: STI is nullptr.\n";
                return 1;
            }
            if (!Inst.getOpcode()) {
                errs() << "Inst has invalid opcode!\n";
                return 1;
            }
            outs() << "trying to print\n";
            outs() << Inst.getNumOperands();
            outs() << STI->getCPU();
            MIP->printInst(&Inst, 0, "", *STI, outs());
            return 0;
        }
    }

    errs() << "Instruction not found: " << InstrName << "\n";
    return 1;
}
