from analysis.globals import *
from typing import List
import csv

# reasoning for decode:
# line 143: DIV	reg/mem16, 144: DIV	reg/mem32
# -> the 16 should be applied to the register apparently otherwise there would be only one general reg entry and single memXX entries


# manual operand decode
op_decode_map = {
    "reg": [Operand(-1, "reg", -1)],
    "reg8": [Operand(-1, "reg", 8)],
    "reg16": [Operand(-1, "reg", 16)],
    "reg32": [Operand(-1, "reg", 32)],
    "reg64": [Operand(-1, "reg", 64)],
    "Imm": [Operand(-1, "imm", -1)],
    "imm": [Operand(-1, "imm", -1)],
    "imm8": [Operand(-1, "imm", 8)],
    "imm16": [Operand(-1, "imm", 16)],
    "imm32": [Operand(-1, "imm", 32)],
    "imm64": [Operand(-1, "imm", 64)],
    "xmm": [Operand(-1, "reg", 128)],
    "xmm0": [Operand(-1, "reg", 128)],
    "<xmm0>": [Operand(-1, "reg", 128, suppressed=True)],
    "xmm1": [Operand(-1, "reg", 128)],
    "xmm2": [Operand(-1, "reg", 128)],
    "xmm3": [Operand(-1, "reg", 128)],
    "xmm4": [Operand(-1, "reg", 128)],
    "ymm1": [Operand(-1, "reg", 256)],
    "ymm2": [Operand(-1, "reg", 256)],
    "ymm3": [Operand(-1, "reg", 256)],
    "ymm4": [Operand(-1, "reg", 256)],
    "zmm1": [Operand(-1, "reg", 512)],
    "zmm2": [Operand(-1, "reg", 512)],
    "zmm3": [Operand(-1, "reg", 512)],
    "zmm4": [Operand(-1, "reg", 512)],
    "{k1}": [Operand(-1, "reg", 64)],
    "k1": [Operand(-1, "reg", 64)],
    "k2": [Operand(-1, "reg", 64)],
    "k3": [Operand(-1, "reg", 64)],
    "mem": [Operand(-1, "mem", -1)],
    "mem8": [Operand(-1, "mem", 8)],
    "mem16": [Operand(-1, "mem", 16)],
    "mem32": [Operand(-1, "mem", 32)],
    "mem64": [Operand(-1, "mem", 64)],
    "mem80": [Operand(-1, "mem", 80)],
    "mem128": [Operand(-1, "mem", 128)],
    "mem256": [Operand(-1, "mem", 256)],
    "mem512": [Operand(-1, "mem", 512)],
    "mem32bcst": [Operand(-1, "mem", 32)],
    "mem64bcst": [Operand(-1, "mem", 64)],
    "vm32x": [Operand(-1, "mem", 32)],
    "memem32": [Operand(-1, "mem", 32)],  # TODO What is this
    "mmx1": [Operand(-1, "reg", 64)],
    "mmx2": [Operand(-1, "reg", 64)],
    "mmx3": [Operand(-1, "reg", 64)],
    "mmx4": [Operand(-1, "reg", 64)],
    "ax": [Operand(-1, "reg", 8)],
    "CL": [Operand(-1, "reg", 8, regList=["CL"])],  # TODO properly handle regLists
}

op_decode_map["reg16/32"] = op_decode_map["reg16"] + op_decode_map["reg32"]
op_decode_map["reg32/64"] = op_decode_map["reg32"] + op_decode_map["reg64"]
op_decode_map["reg16/32/64"] = op_decode_map["reg16/32"] + op_decode_map["reg64"]
op_decode_map["reg8/16/32"] = op_decode_map["reg16/32"] + op_decode_map["reg8"]

op_decode_map["mem16/32"] = op_decode_map["mem16"] + op_decode_map["mem32"]
op_decode_map["mem32/64"] = op_decode_map["mem32"] + op_decode_map["mem64"]
op_decode_map["mem16/32/64"] = op_decode_map["mem16/32"] + op_decode_map["mem64"]

op_decode_map["reg/mem16/32/64"] = op_decode_map["reg16/32/64"] + op_decode_map["mem16/32/64"]
op_decode_map["reg/mem8"] = op_decode_map["reg8"] + op_decode_map["mem8"]
op_decode_map["reg/mem16"] = op_decode_map["reg16"] + op_decode_map["mem16"]
op_decode_map["reg/mem32"] = op_decode_map["reg32"] + op_decode_map["mem32"]
op_decode_map["reg/mem64"] = op_decode_map["reg64"] + op_decode_map["mem64"]


op_decode_map["imm16/32"] = op_decode_map["imm16"] + op_decode_map["imm32"]
op_decode_map["imm8/16/32"] = op_decode_map["imm8"] + op_decode_map["imm16/32"]
op_decode_map["mem128{k0}"] = op_decode_map["mem128"]  # TODO check if this is correct
op_decode_map["mem256{k0}"] = op_decode_map["mem256"]  # TODO check if this is correct
op_decode_map["mem512{k0}"] = op_decode_map["mem512"]  # TODO check if this is correct
op_decode_map["{k1}{z}"] = op_decode_map["{k1}"]
op_decode_map["{k1}{z}{k1}"] = op_decode_map["{k1}"]


def getOpList(op_string: str) -> List[Operand]:
    if op_string is None:
        return [None]
    if op_string in op_decode_map:
        return op_decode_map[op_string]
    # this is not in the list, check if we can add it canonically
    operands = []
    for op in op_string.split("/"):
        if op not in op_decode_map.keys():
            if op != "":
                print(f"unhandled operand: {op}")
            return [None]
        operands += op_decode_map[op]
    op_decode_map[op_string] = operands  # add for future accesses
    return operands


def get_tp(tp_string: str) -> List[Throughput]:
    if tp_string in ["ucode", "variable", "-", ""]:
        return []
    if "-" in tp_string:
        # this is a range
        split = tp_string.split("-")
        return [Throughput(1.0 / float(split[1]), 1.0 / float(split[0]))]
    return [Throughput(1.0 / float(tp_string), 1.0 / float(tp_string))]


def get_lat(lat_string: str) -> List[Latency]:
    if lat_string in ["complex", "ucode", "variable", "-", "?", ""]:
        return []
    if "," in lat_string:
        return [Latency(None, None, float(s), float(s)) for s in lat_string.split(",")]
    return [Latency(None, None, float(lat_string), float(lat_string))]


def parse_zen4_sheet() -> List[Instruction]:
    with open("analysis/reference-files/Zen4_Instruction_Latencies_version_1-00.csv", "r") as f:
        reader = csv.reader(f, delimiter=";")
        rows = [r for r in reader]

    instructions: List[Instruction] = []
    # exclude header
    for row in rows[1:]:
        # unfold operand combinations
        for op1 in getOpList(row[1]):
            for op2 in getOpList(row[2]):
                for op3 in getOpList(row[3]):
                    for op4 in getOpList(row[4]):
                        # if row[5] is not empty, split the operands using /
                        # mask operands in column 5 are always optional, appending None ensures
                        # that a variant of the instruction without this operand is created
                        for optionalOp5 in [p for p in row[5].split("/") if p] + [None]:
                            opList = getOpList(optionalOp5)
                            assert len(opList) == 1  # This should only have one op now as we split manually
                            op5 = opList[0]
                            if row[0] == "RCL":
                                print(f"{row}, {op1=},{op2=},{op3=},{op4=}, {op5=}, {row[5].split("/")=}")
                            inst: Instruction = Instruction()
                            inst.source = "docs"
                            inst.sourceName = row[0]
                            inst.asmName = row[0]
                            if op1 is not None:
                                inst.operands.append(op1)
                            if op2 is not None:
                                inst.operands.append(op2)
                            if op3 is not None:
                                inst.operands.append(op3)
                            if op4 is not None:
                                inst.operands.append(op4)
                            # mask operands return so one variant is added with and without the mask
                            if op5 is not None:
                                inst.operands.append(op5)
                            inst.latencies.extend(get_lat(row[10]))
                            inst.throughputs.extend(get_tp(row[11]))
                            # add metadata
                            inst.metadata["zeroing"] = optionalOp5 is not None and "{z}" in optionalOp5
                            inst.metadata["AVX512"] = row[7] == "AVX512"
                            instructions.append(inst)

    return instructions
