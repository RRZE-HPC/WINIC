from analysis.globals import *
from analysis.parsing.helper import get_AArch64_register_metadata, get_AArch64_register_width, get_x86_register_width
from analysis.parsing.llvm_interface import get_env
from pprint import pprint
import yaml


def _get_llvm_metadata(llvm_name: str, arch: Literal["X86", "AArch64"]):
    llvm_instr = get_env(arch).get_instruction(llvm_name)
    if llvm_instr is None:
        return {}
    metadata = {}
    if arch == "X86":
        metadata["roundc"] = bool(llvm_instr["hasEVEX_RC"]) if "hasEVEX_RC" in llvm_instr else False
        metadata["zeroing"] = "{z}" in llvm_instr["AsmString"]
        # join to also find "AVX512Ii8" etc.
        metadata["avx512"] = "AVX512" in "".join(llvm_instr["!superclasses"]) + "".join(llvm_instr["!locs"])
        if "hasLockPrefix" in llvm_instr:
            metadata["locked"] = bool(llvm_instr["hasLockPrefix"])
    if arch == "AArch64":
        pass
    return metadata


def parse_WINIC_instruction(dbEntry, arch: Literal["X86", "AArch64"]) -> Instruction:
    llvm_name = dbEntry["llvmName"]
    shape_hint = ""
    if arch == "AArch64":
        if "." in dbEntry["name"]:  # e.g. fsqrt.8h
            shape_hint = dbEntry["name"][-1]
        #  parse_instruction has to add the shape to applicable operands. we have to do it this way as llvm does not store that info per operand
        # instruction = parse_LLVM_AArch64_instruction(llvm_name, shape)

    llvm_instr = get_env(arch).get_instruction(llvm_name)
    if llvm_instr is None:
        return None
    instruction = Instruction(source="winic", sourceName=llvm_name)
    instruction.asmName = dbEntry["name"].split()[0]
    instruction.throughputs.append(Throughput(dbEntry.get("throughputMin", None), dbEntry.get("throughputMax", None)))
    instruction.metadata = _get_llvm_metadata(llvm_name, arch)

    for index, db_op in enumerate(dbEntry["operands"]):
        operand = Operand(index + 1, read=db_op["read"], write=db_op["write"], width=-1)

        if db_op["class"] == "immediate":
            operand.type = "imm"
        if db_op["class"] == "memory":
            operand.type = "mem"
            if arch == "AArch64":
                operand.metadata["pre_indexed"] = llvm_name.endswith("pre")
                operand.metadata["post_indexed"] = llvm_name.endswith("post")
        if db_op["class"] == "register":
            operand.type = "reg"
            operand.width = db_op["width"]
            if arch == "X86":
                operand.regList = get_env(arch).expand_regs(db_op["name"])
            if arch == "AArch64":
                operand.metadata = get_AArch64_register_metadata(db_op["name"], shape_hint)

        # Ugly workaround to get memory and immediate width TODO make WINIC generate this info.
        # This assumes at most one immediate or memory operand
        if arch == "X86" and operand.type in ["mem", "imm"]:
            for llvm_op in llvm_instr["InOperandList"]["args"] + llvm_instr["OutOperandList"]["args"]:
                type, width = get_env(arch).identify_x86_LLVM_operand(llvm_op[0]["def"])
                if type == operand.type:
                    operand.width = width
                    break

        instruction.operands.append(operand)
    # parse implicit operands
    operand_latencies = dbEntry.get("operandLatencies", {})
    read = set([lat["sourceOperand"] for lat in operand_latencies if not lat["sourceOperand"].isnumeric()])
    written = set([lat["targetOperand"] for lat in operand_latencies if not lat["targetOperand"].isnumeric()])
    # sort list to ensure deterministic operand order
    for op_name in sorted(list(read.union(written))):
        type = "flags" if op_name == "EFLAGS" else "reg"
        if arch == "X86":
            width = get_x86_register_width(op_name)
        if arch == "AArch64":
            width = get_AArch64_register_width(op_name)
        instruction.operands.append(
            Operand(
                len(instruction.operands) + 1,
                type,
                width,
                op_name in read,
                op_name in written,
                op_name in ["EFLAGS", "MXCSR", "NZCV", "VG", "FFR", "FPCR"],
                ["EFLAGS"] if type == "flags" else [],
            )
        )

    operand_latencies = dbEntry.get("operandLatencies", {})
    for lat in operand_latencies:
        sourceOp: str = lat["sourceOperand"]
        if sourceOp.isnumeric():
            sourceIndex = int(sourceOp) + 1  # uops counts from 1, winic from 0
        else:
            sourceIndex = next(
                (op.index for op in instruction.operands if len(op.regList) == 1 and op.regList[0] == sourceOp), None
            )

        targetOp: str = lat["targetOperand"]
        if targetOp.isnumeric():
            targetIndex = int(targetOp) + 1  # uops counts from 1, winic from 0
        else:
            targetIndex = next(
                (op.index for op in instruction.operands if len(op.regList) == 1 and op.regList[0] == targetOp), None
            )

        if "latencyMin" in lat and "latencyMax" in lat:
            instruction.latencies.append(Latency(sourceIndex, targetIndex, lat["latencyMin"], lat["latencyMax"]))
        else:
            print("database malformed")
            pprint(lat)
            pprint(instruction, compact=True)
            pprint(dbEntry, compact=True)
            exit(1)
    return instruction


def read_WINIC_db(path: str):
    with open(path, "r") as file:
        raw_content = file.read()
    return yaml.safe_load(raw_content)["instructions"]
