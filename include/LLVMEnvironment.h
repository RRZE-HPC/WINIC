#ifndef LLVM_ENVIRONMENT_H
#define LLVM_ENVIRONMENT_H

#include "ErrorCode.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include <memory>
#include <set>
#include <string>
#include <utility>
namespace llvm {
class MCAsmInfo;
}
namespace llvm {
class MCInstPrinter;
}
namespace llvm {
class MCInstrInfo;
}
namespace llvm {
class MCSubtargetInfo;
}
namespace llvm {
class TargetRegisterInfo;
}

using namespace llvm;

class LLVMEnvironment {
  public:
    LLVMContext Ctx;
    Triple TargetTriple;
    std::unique_ptr<Module> Mod;
    std::unique_ptr<TargetMachine> Machine;
    std::unique_ptr<MachineFunction> MF;
    std::unique_ptr<MachineModuleInfo> MMI;
    const TargetRegisterInfo *TRI;
    MCRegisterInfo *MRI;
    MCAsmInfo *MAI;
    MCInstrInfo *MCII;
    MCSubtargetInfo *MSTI;
    MCInstPrinter *MIP;
    unsigned MaxReg;
    Triple::ArchType Arch;

    /**
     * \brief Constructs a new LLVMEnvironment and initializes the LLVM context and module.
     */
    LLVMEnvironment();

    LLVMEnvironment(const LLVMEnvironment &) = delete;
    LLVMEnvironment &operator=(const LLVMEnvironment &) = delete;

    /**
     * \brief Sets up the LLVM environment for the specified architecture and CPU.
     * \param March The target architecture (e.g., "x86_64", "aarch64"). If empty, uses host.
     * \param Cpu The CPU model. If empty, uses host CPU.
     * \return ErrorCode indicating success or failure.
     */
    ErrorCode setUp(std::string March = "", std::string Cpu = "");

    /**
     * \brief Checks if a register belongs to a given register class.
     * \param Reg The register to check.
     * \param RegClass The register class.
     * \return True if Reg is in RegClass, false otherwise.
     */
    bool regInRegClass(MCRegister Reg, MCRegisterClass RegClass);

    /**
     * \brief Checks if a register belongs to a register class by ID.
     * \param Reg The register to check.
     * \param RegClassID The register class ID.
     * \return True if Reg is in the register class, false otherwise.
     */
    bool regInRegClass(MCRegister Reg, unsigned RegClassID);

    /**
     * \brief Converts a register to its string representation.
     * \param Reg The register to convert.
     * \return String representation of the register.
     */
    std::string regToString(MCRegister Reg);

    /**
     * \brief Converts a register class to its string representation.
     * \param RegClass The register class to convert.
     * \return String representation of the register class.
     */
    std::string regClassToString(MCRegisterClass RegClass);

    /**
     * \brief Converts a register class ID to its string representation.
     * \param RegClassID The register class ID.
     * \return String representation of the register class.
     */
    std::string regClassToString(unsigned RegClassID);

    /**
     * \brief Gets the opcode for an instruction by name.
     * \param InstructionName The name of the instruction.
     * \return The opcode, or std::numeric_limits<unsigned>::max() if not found.
     */
    unsigned getOpcode(std::string InstructionName);

    /**
     * \brief Gets all registers which can be read by an instruction, including implicit uses.
     * \param Opcode The instruction opcode.
     * \return Set of MCRegister objects that can be read.
     */
    std::set<MCRegister> getPossibleUses(unsigned Opcode);

    /**
     * \brief Gets all registers which can be written by an instruction, including implicit defs.
     * \param Opcode The instruction opcode.
     * \return Set of MCRegister objects that can be written.
     */
    std::set<MCRegister> getPossibleDefs(unsigned Opcode);

    /**
     * \brief Computes the intersection of two sets of registers.
     * \param A First set of registers.
     * \param B Second set of registers.
     * \return Set containing registers present in both A and B.
     */
    std::set<MCRegister> regIntersect(std::set<MCRegister> A, std::set<MCRegister> B);

    /**
     * \brief Computes the difference of two sets of registers.
     * \param A First set of registers.
     * \param B Second set of registers.
     * \return Set containing registers in A but not in B.
     */
    std::set<MCRegister> regDifference(std::set<MCRegister> A, std::set<MCRegister> B);

    /**
     * \brief Computes the union of two sets of registers.
     * \param A First set of registers.
     * \param B Second set of registers.
     * \return Set containing all registers in A or B.
     */
    std::set<MCRegister> regUnion(std::set<MCRegister> A, std::set<MCRegister> B);
};

#endif // LLVM_ENVIRONMENT_H
