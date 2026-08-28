from analysis.globals import *
from typing import List, Literal
import os
import re
import json

llvm_instructions = {}
llvm_DAGOperands = {}


# TODO implement support for aarch and RISCV
def _loadInstructions(arch: Literal["X86", "AArch64"]):
    global llvm_instructions
    global llvm_DAGOperands
    with open(os.path.join(script_dir, "reference-files", arch + ".json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    data = {
        key: value for key, value in data.items() if key != "!instanceof" and isinstance(value, dict)
    }  # remove large first key
    llvm_instructions = {key: value for key, value in data.items() if "Instruction" in value["!superclasses"]}
    llvm_DAGOperands = {key: value for key, value in data.items() if "DAGOperand" in value["!superclasses"]}


# ---LLVM parsing --- #
# expand one or more reg classes recursively to a list of registes
def _expand_regs(regs: list | str):
    global llvm_DAGOperands
    debug(f"expanding {regs}")

    result_regs = []
    if isinstance(regs, str):
        regs = [regs]
    for reg in regs:
        # weird llvm class
        if reg == "GR16orGR32orGR64":
            result_regs += _expand_regs(["GR16"])
        if reg == "GR32orGR64":
            result_regs += _expand_regs(["GR32"])
        if not reg in llvm_DAGOperands.keys():
            result_regs.append(reg)
            continue
        llvm_reg_class = llvm_DAGOperands[reg]
        if not "MemberList" in llvm_reg_class.keys():
            result_regs.append(reg)  # this not a register class
            continue
        if "%u" in str(llvm_reg_class["MemberList"]["args"]):
            # pattern for registers
            members = llvm_reg_class["MemberList"]["args"]
            base: str = members[0][0]
            # members has pattern and range of numbers to put in pattern
            try:
                result_regs += [base.replace("%u", str(i)) for i in range(members[1][0], members[2][0])]
            except TypeError:
                print(base)
                exit(1)
        else:
            # normal list of registers/registerclasses
            result_regs += _expand_regs([arg[0]["def"] for arg in llvm_reg_class["MemberList"]["args"]])
    # debug(str(list(set(result_regs))[:5]) + "...")
    return list(set(result_regs))


def _get_other_constraint_side(constraint: str, op: str) -> str | None:
    # AI generated
    parts = [part.strip().strip("$") for part in constraint.split("=")]
    if len(parts) != 2:
        return None  # malformed constraint
    if op == parts[0]:
        return parts[1]
    if op == parts[1]:
        return parts[0]
    return None  # op not found


def _get_constraints_items(constraint: str):
    # return all identifiers in constraints without $ e.g. $dst = $src0 -> ["dst", "src0"]
    parts = [part.strip().strip("$") for part in constraint.split("=")]
    return parts


def _get_immidiate_width(imm: str):
    matches = re.findall(r"\d+", imm)
    return int(matches[-1]) if matches else None


def _identify_x86_LLVM_operand(opName):
    from analysis.parsing.helper import get_register_width

    if opName == "EFLAGS":
        return ("flags", None)
    if opName in llvm_DAGOperands:
        operand = llvm_DAGOperands[opName]
        if "OperandType" in operand and operand["OperandType"] == "OPERAND_IMMEDIATE":
            return ("imm", _get_immidiate_width(opName))
        registers = _expand_regs(opName)
    else:
        registers = [opName]

    return ("reg", get_register_width(registers[0]))


def parse_LLVM_x86_instruction(LLVMName: str) -> Instruction:
    global llvm_DAGOperands
    global llvm_instructions
    if len(llvm_instructions) == 0:
        _loadInstructions("X86")
    # idk why some are missing
    if LLVMName not in llvm_instructions:
        return None

    l_inst = llvm_instructions[LLVMName]
    inOperandList = l_inst["InOperandList"]["args"]
    outOperandList = l_inst["OutOperandList"]["args"]
    constraints: str = l_inst["Constraints"]
    defs = l_inst["Defs"]
    uses = l_inst["Uses"]
    
    inst = Instruction("winic", LLVMName, l_inst["AsmString"], [], [], [], {})
    inst.metadata["roundc"] = False

    # parse operands
    index = 1
    for op in outOperandList:
        if op[1] == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        if op[0]["def"] == "AVX512RC":  # llvm has this as operand, uops as flag
            inst.metadata["roundc"] = True
            continue
        type, width = _identify_x86_LLVM_operand(op[0]["def"])
        if type is None:
            return None
        elif type == "imm":
            operand = Operand(index, type, width, False, True, False, [])
        else:
            operand = Operand(index, type, width, False, True, False, _expand_regs(op[0]["def"]))
        inst.operands.append(operand)
        index += 1

    for op in inOperandList:
        if op[1] == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        if op[0]["def"] == "AVX512RC":  # llvm has this as operand, uops as flag
            inst.metadata["roundc"] = True
            continue
        # process constraints
        wasConstrained = False
        for constraint in constraints.split(","):
            if op[1] is None:
                print("op[1] None")
                return None
            if op[1] not in _get_constraints_items(constraint):
                continue
            wasConstrained = True
            # we have to set "read" to True in corresponding def
            dstOp = _get_other_constraint_side(constraint, op[1])
            if dstOp is None:
                continue
            defIndex = next((i + 1 for i, defOp in enumerate(outOperandList) if defOp[1] == dstOp), None)
            if defIndex is None:
                return None
            for operand in inst.operands:
                if operand.index == defIndex:
                    operand.read = True
                    break
        if wasConstrained:
            continue  # do not have to add operand an additional time
        type, width = _identify_x86_LLVM_operand(op[0]["def"])
        if type is None:
            return None
        elif type == "imm":
            operand = Operand(index, type, width, True, False, False, [])
        else:
            operand = Operand(index, type, width, True, False, False, _expand_regs(op[0]["def"]))
        inst.operands.append(operand)
        index += 1

    # process defs and uses
    for d in defs:
        opName = d["def"]
        if opName == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        type, width = _identify_x86_LLVM_operand(opName)
        if type is None:
            return None
        write = True
        read = True if d in uses else False
        regList = [opName] if type == "reg" else []
        if len(regList) == 0:
            regList = ["EFLAGS"] if type == "flags" else []
        # TODO this is not very good yet, there are other registers that are supressed but in here
        suppressed = opName in ["EFLAGS"]
        operand = Operand(index, type, width, read, write, suppressed, regList)
        inst.operands.append(operand)
        index += 1
    for d in uses:
        if d in defs:
            continue  # already added
        opName = d["def"]
        if opName == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        type, width = _identify_x86_LLVM_operand(opName)
        if type is None:
            return None
        write = False
        read = True
        regList = [opName] if type == "reg" else []
        if len(regList) == 0:
            regList = ["EFLAGS"] if type == "flags" else []
        suppressed = opName in ["EFLAGS"]  # TODO this is not very good yet
        operand = Operand(index, type, width, read, write, suppressed, regList)
        inst.operands.append(operand)
        index += 1
    
    inst.metadata["zeroing"] = "{z}" in l_inst["AsmString"]
    # join to also find "AVX512Ii8" etc.
    inst.metadata["AVX512"] = "AVX512" in "".join(l_inst["!superclasses"]) + "".join(l_inst["!locs"])
    return inst


# does not parse pseudo instructions
# normal operands get indices, defs/uses dont get indices
def parse_LLVM_AArch64_instruction(LLVMName: str, shapeHint: str = "") -> Instruction:
    from analysis.parsing.helper import get_aarch_operands

    global llvm_DAGOperands
    global llvm_instructions
    if len(llvm_instructions) == 0:
        _loadInstructions("AArch64")
    # idk why some are missing
    if LLVMName not in llvm_instructions:
        return None

    l_inst = llvm_instructions[LLVMName]
    if l_inst["AsmString"] == "":
        return None
    inOperandList = l_inst["InOperandList"]["args"]
    outOperandList = l_inst["OutOperandList"]["args"]
    constraints: str = l_inst["Constraints"]
    defs = l_inst["Defs"]
    uses = l_inst["Uses"]
    # convert operands
    operandList: List[Operand] = []
    index = 1
    for op in outOperandList:
        if op is None:
            return None
        for operand in get_aarch_operands(op[0]["def"], shapeHint):
            operand.index = index
            operand.read = False
            operand.write = True
            operandList.append(operand)
            index += 1
    for op in inOperandList:
        if op is None:
            return None
        # process constraints
        wasConstrained = False
        for constraint in constraints.split(","):
            if op[1] is None:
                print("op[1] None")
                return None
            if op[1] not in _get_constraints_items(constraint):
                continue
            wasConstrained = True
            # we have to set "read" to True in corresponding def
            dstOp = _get_other_constraint_side(constraint, op[1])
            if dstOp is None:
                continue
            defIndex = next((i + 1 for i, defOp in enumerate(outOperandList) if defOp[1] == dstOp), None)
            if defIndex is None:
                return None
            for operand in operandList:
                if operand.index == defIndex:
                    operand.read = True
                    break
        if wasConstrained:
            continue  # do not have to add operand an additional time
        for operand in get_aarch_operands(op[0]["def"], shapeHint):
            if operand is None:
                continue
            operand.index = index
            operand.read = True
            operand.write = False
            operandList.append(operand)
            index += 1

    # process defs and uses
    for d in defs:
        for operand in get_aarch_operands(d["def"], shapeHint):
            if operand is None:
                return None
            operand.write = True
            operand.read = True if d in uses else False
            operandList.append(operand)
            index += 1
    for d in uses:
        if d in defs:
            continue  # already added
        for operand in get_aarch_operands(d["def"], shapeHint):
            if operand is None:
                return None
            operand.write = False
            operand.read = True
            operandList.append(operand)
            index += 1
    inst = Instruction("winic", LLVMName, l_inst["AsmString"], operandList, [], [], {})
    return inst


if __name__ == "__main__":
    import yaml

    with open("ISC/a_v2/old/winic_v2_r4.yaml", "r") as f:
        raw_content = f.read()
    db = yaml.safe_load(raw_content)
    _loadInstructions("AArch64")
    for inst in db:
        parse_LLVM_AArch64_instruction(inst["llvmName"])
