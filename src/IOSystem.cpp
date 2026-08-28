#include "IOSystem.h"

#include "AssemblyFile.h"
#include "CustomDebug.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "LLVMDebug.h"
#include "LLVMEnvironment.h"
#include "version.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <exception>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <system_error>

namespace winic {

std::pair<ErrorCode, IOInstruction> createOpInstruction(unsigned Opcode) {
    InstructionForm instructionForm = InstructionForm(Opcode);
    std::vector<IOOperand> operands;

    // make sure operands are sorted
    instructionForm.sortOperands();
    for (OperandForm operandForm : instructionForm.getOperands()) {
        IOOperand opOp;
        if (operandForm.isRegClass()) {
            opOp.opClass = "register";
            opOp.name = opOp.name =
                std::make_optional(str(getEnv().MRI->getRegClass(operandForm.getRegClassID())));
        } else if (operandForm.isImmediate()) {
            opOp.opClass = "immediate";
        } else if (operandForm.isMemory()) {
            opOp.opClass = "memory";
        } else
            continue;
        opOp.write = operandForm.isDef();
        opOp.read = operandForm.isUse();
        operands.emplace_back(opOp);
    }
    IOInstruction opInst;
    opInst.llvmName = instructionForm.getName();

    // get mnemonic
    MCInst inst;
    inst.setOpcode(Opcode);
    auto [iName, _] = getEnv().MIP->getMnemonic(inst);
    if (!iName) return {S_NO_MNEMONIC, {}};

    std::string s = iName;
    // remove trailing spaces
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char Ch) { return !std::isspace(Ch); })
                .base(),
            s.end());
    opInst.name = s;
    opInst.operands = operands;
    opInst.latencies = {};
    opInst.latency = std::nullopt;
    opInst.throughput = std::nullopt;
    opInst.throughputMin = std::nullopt;
    opInst.throughputMax = std::nullopt;
    return {SUCCESS, opInst};
}

ErrorCode updateDatabaseEntryTP(TPMeasurement M) {
    double lowerTP = std::round(M.lowerTP * 100) / 100;
    double upperTP = std::round(M.upperTP * 100) / 100;
    std::string name = getEnv().MCII->getName(M.opcode).str();
    auto it = std::find_if(ioFile.instructions.begin(), ioFile.instructions.end(),
                           [&](const IOInstruction &Inst) { return Inst.llvmName == name; });
    if (it != ioFile.instructions.end()) {
        dbg(__func__, "update ", name, " throughput: ", lowerTP, " ", upperTP);
        // Found entry, update it if the new measurement did not have an error
        if (!isError(M.ec)) {
            it->throughput = lowerTP;
            it->throughputMin = lowerTP;
            it->throughputMax = upperTP;
        }
    } else {
        dbg(__func__, "insert ", name, " throughput: ", lowerTP, " ", upperTP);
        // Not found, insert
        auto [EC, opInst] = createOpInstruction(M.opcode);
        if (EC != SUCCESS) return EC;
        if (isError(M.ec)) {
            opInst.throughput = std::nullopt;
            opInst.throughputMin = std::nullopt;
            opInst.throughputMax = std::nullopt;
        } else {
            opInst.throughput = lowerTP;
            opInst.throughputMin = lowerTP;
            opInst.throughputMax = upperTP;
        }
        ioFile.instructions.push_back(opInst);
    }
    return SUCCESS;
}

ErrorCode updateDatabaseEntryLAT(LatMeasurement M) {
    InstructionForm instructionForm = InstructionForm(M.opcode);

    std::string useIndexString = std::to_string(M.useIndex);
    std::string defIndexString = std::to_string(M.defIndex);
    if (auto *regOp = std::get_if<RegisterOperand>(&M.type.useOp))
        useIndexString = getEnv().MRI->getName(regOp->getRegister());
    if (auto *regOp = std::get_if<RegisterOperand>(&M.type.defOp))
        defIndexString = getEnv().MRI->getName(regOp->getRegister());
    auto ioInstr = std::find_if(
        ioFile.instructions.begin(), ioFile.instructions.end(),
        [&](const IOInstruction &Inst) { return Inst.llvmName == instructionForm.getName(); });
    if (ioInstr == ioFile.instructions.end()) {
        // Not found, create first
        auto [EC, opInst] = createOpInstruction(M.opcode);
        if (EC != SUCCESS) return EC;
        ioFile.instructions.push_back(opInst);
    }
    ioInstr = std::find_if(
        ioFile.instructions.begin(), ioFile.instructions.end(),
        [&](const IOInstruction &Inst) { return Inst.llvmName == instructionForm.getName(); });

    std::optional<double> min =
        isError(M.ec) ? std::nullopt : std::optional<double>(std::round(M.lowerBound * 10) / 10);
    std::optional<double> max =
        isError(M.ec) ? std::nullopt : std::optional<double>(std::round(M.upperBound * 10) / 10);
    auto latencyEntry = std::find_if(
        ioInstr->latencies.begin(), ioInstr->latencies.end(), [&](const IOLatency &Lat) {
            return Lat.sourceOperand == useIndexString && Lat.targetOperand == defIndexString;
        });
    if (latencyEntry != ioInstr->latencies.end()) {
        // Found entry, update it if the new measurement did not have an error
        if (!isError(M.ec)) {
            latencyEntry->min = min;
            latencyEntry->max = max;
        }
    } else {
        // no entry with this src target combination, add it
        IOLatency lat;
        lat.sourceOperand = useIndexString;
        lat.targetOperand = defIndexString;
        lat.min = min;
        lat.max = max;
        ioInstr->latencies.insert(ioInstr->latencies.end(), lat);
    }
    // take maximum latency value as instruction latency
    ioInstr->latency = 0;
    for (IOLatency lat : ioInstr->latencies)
        ioInstr->latency = std::max(ioInstr->latency, lat.max);

    return SUCCESS;
}

ErrorCode loadYaml(std::string Path) {
    auto buffer = llvm::MemoryBuffer::getFile(Path);
    if (!buffer) {
        std::cerr << "Failed to open file: " << Path << std::endl;
        return E_FILE;
    }
    llvm::yaml::Input yin(buffer->get()->getBuffer());
    try {
        yin >> ioFile;
    } catch (const std::exception &e) {
        std::cerr << "YAML serialization error: " << e.what() << std::endl;
        return E_FILE;
    }
    if (yin.error()) { // check for parse/serialization errors
        std::cerr << "YAML parsing failed for file: " << Path << std::endl;
        return E_FILE;
    }

    if (ioFile.version != WINIC_VERSION) {
        std::cout << str("WARNING: The database ", Path,
                         " was created with a different version of WINIC. Database: ",
                         ioFile.version, " Current: ", WINIC_VERSION)
                  << std::endl;
    }
    return SUCCESS;
}

ErrorCode saveYaml(std::string Path) {
    if (!keepEmptyEntries) stripOutputDatabase();
    // remove tabs from mnemonics
    for (IOInstruction &inst : ioFile.instructions) {
        inst.name = replaceAllInstances(inst.name, "\t", "   ");
    }
    ioFile.version = WINIC_VERSION;
    ioFile.microArchitecture = getEnv().Machine->getTargetCPU().data();
    switch (getEnv().TargetTriple.getArch()) {
    case Triple::ArchType::x86_64:
        ioFile.isa = "x86";
        break;
    case Triple::ArchType::aarch64:
        ioFile.isa = "aarch64";
        break;
    case Triple::ArchType::riscv64:
        ioFile.isa = "riscv";
        break;
    default:
        out(std::cerr, "Unsupported architecture, this should be unreachable.");
        return E_UNREACHABLE;
    }

    std::error_code ec;
    llvm::raw_fd_ostream fout(Path, ec);
    if (ec) {
        std::cerr << "Failed to open file: " << Path << std::endl;
        return E_FILE;
    }
    llvm::yaml::Output yout(fout);
    dbg(__func__, "writing ", ioFile.instructions.size(), " entries to ", Path);
    try {
        yout << ioFile;
    } catch (const std::exception &e) {
        std::cerr << "YAML serialization error: " << e.what() << std::endl;
        return E_FILE;
    }
    return SUCCESS;
}

void stripOutputDatabase() {
    std::vector<IOInstruction> strippedDatabase;
    for (IOInstruction &inst : ioFile.instructions) {
        bool hasValue = false;
        if (inst.throughput.has_value()) hasValue = true;
        for (auto &lat : inst.latencies) {
            if (lat.min.has_value() || lat.max.has_value()) {
                hasValue = true;
                break;
            }
        }
        if (hasValue) strippedDatabase.push_back(inst);
    }
    ioFile.instructions = strippedDatabase;
}

} // namespace winic
