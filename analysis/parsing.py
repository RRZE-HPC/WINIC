from .globals import *
from typing import List, Literal
from pprint import pprint
import os
import re
import xml.etree.ElementTree as ET
import json

llvm_instructions = {}
llvm_DAGOperands = {}


# TODO implement support for aarch and RISCV
def _loadInstructions(arch: Literal["X86"]):
    global llvm_instructions
    global llvm_DAGOperands
    with open(os.path.join(script_dir, "reference-files", arch + ".json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    data = {
        key: value for key, value in data.items() if key != "!instanceof" and isinstance(value, dict)
    }  # remove large first key
    llvm_instructions = {key: value for key, value in data.items() if "Instruction" in value["!superclasses"]}
    llvm_DAGOperands = {key: value for key, value in data.items() if "DAGOperand" in value["!superclasses"]}


# --- uops parsing --- #
def _parse_uops_operand(op: ET.Element) -> Operand:
    index = int(op.attrib["idx"]) if "idx" in op.attrib else None
    type = op.attrib["type"] if "type" in op.attrib else None
    if index is None:
        return None
    if type not in ["reg", "imm", "flags"]:
        return None

    read = bool(int(op.attrib.get("r", "0")))
    write = bool(int(op.attrib.get("w", "0")))
    suppressed = bool(int(op.attrib.get("suppressed", "0")))

    if op.text == "0" or op.text == 1:
        return None  # ignore fixed immediates
    if op.text is not None:
        regList = op.text.split(",")
    elif type == "flags":
        regList = ["EFLAGS"]
    else:
        regList = []

    if len(regList) == 1:
        # for some reason fixed registers dont have a width in uops database :(
        width = _get_register_width(regList[0])
    else:
        width = int(op.attrib["width"]) if "width" in op.attrib else None
    return Operand(index, type, width, read, write, suppressed, regList)


def _parse_uops_latency(lat: ET.Element) -> Latency:
    try:
        startOp = int(lat.attrib["start_op"])
        targetOp = int(lat.attrib["target_op"])
        cycles = int(lat.attrib["cycles"])
    except KeyError:
        # happens e.g. on latency values regarding memory
        return None
    return Latency(startOp, targetOp, cycles, cycles)


def _parse_uops_instruction(entry: ET.Element, arch: str):
    if (
        (u_arch := entry.find(f"architecture[@name='{arch}']")) is None
        or (u_operands := entry.findall("operand")) is None
        or (u_m := u_arch.find("measurement")) is None
        or (u_lat := u_m.findall("latency")) is None
    ):
        return None
    operands = [_parse_uops_operand(op) for op in u_operands]
    if None in operands:
        return None  # cannot parse all operands
    latencies = [_parse_uops_latency(lat) for lat in u_lat]
    try:
        throughput = float(u_m.attrib["TP_loop"])
        uopsAsm = entry.attrib["asm"]
    except KeyError:
        return None
    uopsName = entry.attrib["string"] if "string" in entry.attrib else ""
    roundc = bool(int(entry.attrib["roundc"])) if "roundc" in entry.attrib else False

    return Instruction(uopsAsm, operands, throughput, throughput, latencies, uopsName, roundc)


def parse_uops_database(arch: str) -> List[Instruction]:
    root = ET.parse(os.path.join(script_dir, "reference-files", "uops.xml"))
    u_instrNodes = root.findall(f".//instruction")
    instructions = []
    for entry in u_instrNodes:
        inst = _parse_uops_instruction(entry, arch)
        if inst is not None:
            instructions.append(inst)
    return instructions


# ---LLVM/WINIC parsing --- #
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


def _get_register_width(reg_name: str) -> int | None:
    """Return the bit-width of the given LLVM register name for x86.

    Returns:
        int: Width in bits, or None if unknown.
    """
    # AI generated
    # Normalize name (in case someone passes lowercase)
    reg = reg_name.upper()

    # Specific register widths
    known_widths = {
        # FLAGS
        "EFLAGS": None,  # 32,
        "RFLAGS": 64,
        "MXCSR": 32,
        # IP registers
        "IP": 16,
        "EIP": 32,
        "RIP": 64,
        # Segment registers
        "CS": 16,
        "DS": 16,
        "ES": 16,
        "FS": 16,
        "GS": 16,
        "SS": 16,
        # Base addresses
        "FS_BASE": 64,
        "GS_BASE": 64,
        "SSP": 64,
        # MMX
        **{f"MM{i}": 64 for i in range(8)},
        # "MM0": 64, "MM1": 64, "MM2": 64, "MM3": 64, "MM4": 64, "MM5": 64, "MM6": 64, "MM7": 64,
        # FPU registers
        "ST0": 80,
        "ST1": 80,
        "ST2": 80,
        "ST3": 80,
        "ST4": 80,
        "ST5": 80,
        "ST6": 80,
        "ST7": 80,
        "FP0": 80,
        "FP1": 80,
        "FP2": 80,
        "FP3": 80,
        "FP4": 80,
        "FP5": 80,
        "FP6": 80,
        "FP7": 80,
        "FPCW": 16,
        "FPSW": 16,
        # AVX mask registers
        **{f"K{i}": 64 for i in range(8)},
        # Debug & control registers (assume full machine word)
        # **{f"DR{i}": 64 for i in range(16)},
        **{f"CR{i}": 64 for i in range(16)},
        # # Tile registers (AMX)
        # **{f"TMM{i}": 8192 for i in range(8)},
        # "TMMCFG": 64,
    }

    # If it's directly known
    if reg in known_widths:
        return known_widths[reg]
    k_regs = {f"K{i}": 64 for i in range(8)}
    if reg in k_regs:
        return 64

    # Register suffix patterns
    if reg.endswith("B"):  # 8-bit (low)
        return 8
    if reg.endswith("BH"):  # 8-bit (high byte)
        return 8
    if reg.endswith("L"):  # 8-bit (low byte)
        return 8
    if reg.endswith("H"):  # High byte (usually 8-bit)
        if len(reg) <= 3:  # AH, BH, etc.
            return 8
        if reg.endswith("WH"):  # e.g. R10WH
            return 16
        return 8
    if reg.endswith("W"):  # 16-bit
        return 16
    if reg in {"AX", "BX", "CX", "DX", "SI", "DI", "SP", "BP", "IP"}:
        return 16
    if reg.endswith("D"):  # 32-bit
        return 32
    if reg.startswith("E") and len(reg) == 3:  # EAX, EBX, etc.
        return 32
    if reg.startswith("R") and reg[1:].isdigit():  # R8, R10, etc.
        return 64
    if reg.startswith("R") and len(reg) >= 3 and reg[2] not in "BDWH":  # RAX, RBP, etc.
        return 64
    if reg in {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP"}:
        return 64

    # SIMD vector registers
    if reg.startswith("XMM"):
        return 128
    if reg.startswith("YMM"):
        return 256
    if reg.startswith("ZMM"):
        return 512

    # print(f"unhandled register: {reg_name}")
    return None  # Unknown


def _identify_LLVM_operand(opName):
    if opName == "EFLAGS":
        return ("flags", None)
    if opName in llvm_DAGOperands:
        operand = llvm_DAGOperands[opName]
        if "OperandType" in operand and operand["OperandType"] == "OPERAND_IMMEDIATE":
            return ("imm", _get_immidiate_width(opName))
        registers = _expand_regs(opName)
    else:
        registers = [opName]

    return ("reg", _get_register_width(registers[0]))


def _parse_LLVM_instruction(LLVMName) -> Instruction:
    global llvm_DAGOperands
    global llvm_instructions
    # idk why some are missing
    if LLVMName not in llvm_instructions:
        return None

    inst = llvm_instructions[LLVMName]
    inOperandList = inst["InOperandList"]["args"]
    outOperandList = inst["OutOperandList"]["args"]
    constraints: str = inst["Constraints"]
    defs = inst["Defs"]
    uses = inst["Uses"]
    # convert operands
    operandList: List[Operand] = []
    index = 1
    roundc = False

    for op in outOperandList:
        if op[1] == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        if op[0]["def"] == "AVX512RC":  # llvm has this as operand, uops as flag
            roundc = True
            continue
        type, width = _identify_LLVM_operand(op[0]["def"])
        if type is None:
            return None
        elif type == "imm":
            operand = Operand(index, type, width, False, True, False, [])
        else:
            operand = Operand(index, type, width, False, True, False, _expand_regs(op[0]["def"]))
        operandList.append(operand)
        index += 1
    for op in inOperandList:
        if op[1] == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        if op[0]["def"] == "AVX512RC":  # llvm has this as operand, uops as flag
            roundc = True
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
            for operand in operandList:
                if operand.index == defIndex:
                    operand.read = True
                    break
        if wasConstrained:
            continue  # do not have to add operand an additional time
        type, width = _identify_LLVM_operand(op[0]["def"])
        if type is None:
            return None
        elif type == "imm":
            operand = Operand(index, type, width, True, False, False, [])
        else:
            operand = Operand(index, type, width, True, False, False, _expand_regs(op[0]["def"]))
        operandList.append(operand)
        index += 1

    # process defs and uses
    for d in defs:
        opName = d["def"]
        if opName == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        type, width = _identify_LLVM_operand(opName)
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
        operandList.append(operand)
        index += 1
    for d in uses:
        if d in defs:
            continue  # already added
        opName = d["def"]
        if opName == "MXCSR":  # uops handles this as a flag, so we dont need it
            continue
        type, width = _identify_LLVM_operand(opName)
        if type is None:
            return None
        write = False
        read = True
        regList = [opName] if type == "reg" else []
        if len(regList) == 0:
            regList = ["EFLAGS"] if type == "flags" else []
        suppressed = opName in ["EFLAGS"]  # TODO this is not very good yet
        operand = Operand(index, type, width, read, write, suppressed, regList)
        operandList.append(operand)
        index += 1
    return Instruction(inst["AsmString"], operandList, None, None, [], "", roundc)


def parse_WINIC_instruction(dbEntry) -> Instruction:
    instruction = _parse_LLVM_instruction(dbEntry["llvmName"])
    if instruction is None:
        return None
    instruction.throughput_lower = dbEntry.get("throughputMin", None)
    instruction.throughput_upper = dbEntry.get("throughputMax", None)
    operand_latencies = dbEntry.get("operandLatencies", {})
    for lat in operand_latencies:
        sourceOp: str = lat["sourceOperand"]
        # if "ADC16ri" in dbEntry["llvmName"]:
        #     print(lat)
        #     print(lat["sourceOperand"])
        #     exit(1)
        targetOp = lat["targetOperand"]
        if sourceOp.isnumeric():
            sourceIndex = int(sourceOp) + 1  # uops counts from 1, winic from 0
        else:
            # need to find index generated for that operand by parse_LLVM_instruction
            sourceIndex = next(
                (op.index for op in instruction.operands if len(op.regList) == 1 and op.regList[0] == sourceOp), None
            )
        if targetOp.isnumeric():
            targetIndex = int(targetOp) + 1  # uops counts from 1, winic from 0
        else:
            # need to find index generated for that operand by parse_LLVM_instruction
            targetIndex = next(
                (op.index for op in instruction.operands if len(op.regList) == 1 and op.regList[0] == targetOp), None
            )
        if "latencyMin" in lat and "latencyMax" in lat:
            instruction.latencies.append(Latency(sourceIndex, targetIndex, lat["latencyMin"], lat["latencyMax"]))
        else:
            pprint(lat)  # database malformed
            pprint(instruction, compact=True)
            pprint(dbEntry, compact=True)
            exit(1)
    return instruction


_loadInstructions("X86")
