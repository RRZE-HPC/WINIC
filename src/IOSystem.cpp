#include "IOSystem.h"

#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include <CustomDebug.h>
#include <ErrorCode.h>
#include <Globals.h>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <string>

namespace winic {

std::pair<ErrorCode, IOInstruction> createOpInstruction(unsigned Opcode) {
    // create yaml output
    std::vector<IOOperand> operands;
    const MCInstrDesc &desc = getEnv().MCII->get(Opcode);
    // stores def operands which are also used (to set the flag)
    std::set<unsigned> tiedToOps;
    // for (auto opInfo : desc.operands()) {
    for (unsigned i = desc.getNumOperands(); i-- > 0;) {
        const MCOperandInfo &opInfo = desc.operands()[i];
        if (opInfo.Constraints & (1 << MCOI::TIED_TO)) {
            // this operand must be identical to another operand
            unsigned tiedToOp = (opInfo.Constraints >> (4 + MCOI::TIED_TO * 4)) & 0xF;
            // we are going backwards, so uses come first. If the use operand is tied to a def, this
            // def has to be marked. marked defs get the "read" flag when they are being processed
            // later
            tiedToOps.insert(tiedToOp);
            continue;
        }
        IOOperand opOp;
        if (opInfo.OperandType == MCOI::OPERAND_REGISTER) {
            opOp.opClass = "register";
            opOp.name = std::make_optional(getEnv().regClassToString(opInfo.RegClass));
            opOp.write = i < desc.getNumDefs();
            opOp.read = !opOp.write;
            // check if this is a use or a def marked as being used
            if (i >= desc.getNumDefs() || tiedToOps.find(i) != tiedToOps.end()) {
                opOp.read = true;
            }

        } else if (opInfo.OperandType == MCOI::OPERAND_IMMEDIATE) {
            opOp.opClass = "immediate";
            opOp.imd = std::make_optional("int");
            opOp.read = true;
            opOp.write = false;
        } else if (opInfo.OperandType == MCOI::OPERAND_MEMORY)
            continue; // TODO memory
        else
            continue;
        operands.insert(operands.begin(), opOp);
    }
    IOInstruction opInst;
    opInst.llvmName = getEnv().MCII->getName(Opcode).str();

    MCInst inst;
    inst.setOpcode(Opcode);
    auto [iName, _] = getEnv().MIP->getMnemonic(inst);
    if (!iName) return {S_NO_MNEMONIC, {}};

    std::string s = iName;
    // remove trailing spaces
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); })
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
    auto it = std::find_if(outputDatabase.begin(), outputDatabase.end(),
                           [&](const IOInstruction &Inst) { return Inst.llvmName == name; });
    if (it != outputDatabase.end()) {
        dbg(__func__, "update ", name, " throughput: ", lowerTP, " ", upperTP);
        // Found entry, update it:
        it->throughput = lowerTP;
        it->throughputMin = lowerTP;
        it->throughputMax = upperTP;
    } else {
        dbg(__func__, "insert ", name, " throughput: ", lowerTP, " ", upperTP);
        // Not found, insert
        auto [EC, opInst] = createOpInstruction(M.opcode);
        if (EC != SUCCESS) return EC;
        if (isError(M.ec)) {
            opInst.throughput = 0;
            opInst.throughputMin = 0;
            opInst.throughputMax = 0;
        } else {
            opInst.throughput = lowerTP;
            opInst.throughputMin = lowerTP;
            opInst.throughputMax = upperTP;
        }
        outputDatabase.push_back(opInst);
    }
    return SUCCESS;
}

unsigned llvmOpNumToNormalOpNum(unsigned OpNum, const MCInstrDesc &Desc) {
    unsigned correctedOpNum = OpNum;
    if (OpNum >= Desc.getNumDefs()) {
        // this is a use operand, may have to shift it
        unsigned shiftAmount = 0;
        for (unsigned i = Desc.getNumDefs(); i <= OpNum && i < Desc.getNumOperands(); i++) {
            const MCOperandInfo &opInfo = Desc.operands()[i];
            if (opInfo.Constraints & (1 << MCOI::TIED_TO)) {
                // this operand is tied to another operand, therefore a duplicate
                shiftAmount++;
            }
        }
        correctedOpNum -= shiftAmount;
    }
    return correctedOpNum;
}

ErrorCode updateDatabaseEntryLAT(LatMeasurement M) {
    std::string name = getEnv().MCII->getName(M.opcode).str();
    const MCInstrDesc &desc = getEnv().MCII->get(M.opcode);
    unsigned correctedUseIndex = llvmOpNumToNormalOpNum(M.useIndex, desc);

    std::string useIndexString = std::to_string(correctedUseIndex);
    std::string defIndexString = std::to_string(M.defIndex);
    if (M.type.useOp.isRegister())
        useIndexString = getEnv().MRI->getName(M.type.useOp.getRegister());
    if (M.type.defOp.isRegister())
        defIndexString = getEnv().MRI->getName(M.type.defOp.getRegister());
    auto instruction =
        std::find_if(outputDatabase.begin(), outputDatabase.end(),
                     [&](const IOInstruction &Inst) { return Inst.llvmName == name; });
    if (instruction == outputDatabase.end()) {
        // Not found, create first
        auto [EC, opInst] = createOpInstruction(M.opcode);
        if (EC != SUCCESS) return EC;
        outputDatabase.push_back(opInst);
    }
    instruction = std::find_if(outputDatabase.begin(), outputDatabase.end(),
                               [&](const IOInstruction &Inst) { return Inst.llvmName == name; });
    auto latencyEntry = std::find_if(
        instruction->latencies.begin(), instruction->latencies.end(), [&](const IOLatency &Lat) {
            return Lat.sourceOperand == useIndexString && Lat.targetOperand == defIndexString;
        });
    std::optional<double> min =
        isError(M.ec) ? std::nullopt : std::optional<double>(std::round(M.lowerBound));
    std::optional<double> max =
        isError(M.ec) ? std::nullopt : std::optional<double>(std::round(M.upperBound));
    if (latencyEntry != instruction->latencies.end()) {
        // Found entry, update it:
        latencyEntry->min = min;
        latencyEntry->max = max;
    } else {
        // no entry with this src target combination, add it
        IOLatency lat;
        lat.sourceOperand = useIndexString;
        lat.targetOperand = defIndexString;
        lat.min = min;
        lat.max = max;
        instruction->latencies.insert(instruction->latencies.end(), lat);
    }
    // take maximum latency value as instruction latency
    instruction->latency = std::max(instruction->latency, max);

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
        yin >> outputDatabase;
    } catch (const std::exception &e) {
        std::cerr << "YAML serialization error: " << e.what() << "\n";
        return E_FILE;
    }
    return SUCCESS;
}

ErrorCode saveYaml(std::string Path) {
    std::error_code ec;
    llvm::raw_fd_ostream fout(Path, ec);
    if (ec) {
        std::cerr << "Failed to open file: " << Path << std::endl;
        return E_FILE;
    }
    llvm::yaml::Output yout(fout);
    dbg(__func__, "writing ", outputDatabase.size(), " entries to ", Path);
    try {
        yout << outputDatabase;
    } catch (const std::exception &e) {
        std::cerr << "YAML serialization error: " << e.what() << "\n";
        return E_FILE;
    }
    return SUCCESS;
}

} // namespace winic
