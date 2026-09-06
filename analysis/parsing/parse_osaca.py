import copy
import itertools
import yaml
from analysis.globals import *
from typing import List


# manual operand decode
op_name_map = {  # x86
    "*": [Operand(-1, "reg", -1)],
    "gpr": [Operand(-1, "reg", 8), Operand(-1, "reg", 16), Operand(-1, "reg", 32), Operand(-1, "reg", 64)],
    "xmm": [Operand(-1, "reg", 128)],
    "ximm": [Operand(-1, "reg", 128)],
    "ymm": [Operand(-1, "reg", 256)],
    "zmm": [Operand(-1, "reg", 512)],
    "mm": [Operand(-1, "reg", 64)],
    "k": [Operand(-1, "reg", 64)],
}
op_prefix_map = {  # AArch64
    "w": [Operand(-1, "reg", 32, metadata={"prefix": "w"})],
    "x": [Operand(-1, "reg", 64, metadata={"prefix": "x"})],
    "h": [Operand(-1, "reg", 16, metadata={"prefix": "h"})],
    "s": [Operand(-1, "reg", 32, metadata={"prefix": "s"})],
    "d": [Operand(-1, "reg", 64, metadata={"prefix": "d"})],
    "q": [Operand(-1, "reg", 128, metadata={"prefix": "q"})],
    "z": [Operand(-1, "reg", -1, metadata={"prefix": "z"})],
    "p": [Operand(-1, "reg", -1, metadata={"prefix": "p"})],
    "v": [Operand(-1, "reg", -1, metadata={"prefix": "v"})],
    # "*": [Operand(-1, "reg", 16), Operand(-1, "reg", 32), Operand(-1, "reg", 64), Operand(-1, "reg", 128)],
    "*": [Operand(-1, "reg", -1)],
}


def parse_osaca_database(path: str) -> List[Instruction]:
    with open(path, "r") as f:
        raw_content = f.read().replace("\t", "    ")  # yaml does not like tabs
    db = yaml.safe_load(raw_content)

    instructions: List[Instruction] = []
    # exclude header
    for entry in db["instruction_forms"]:
        names = entry["name"]
        for name in names if isinstance(names, list) else [names]:
            operand_lists = []
            for operand in entry["operands"]:
                if operand["class"] == "identifier":
                    operand_lists.append([Operand(type="imm")])
                    continue
                elif operand["class"] == "immediate":
                    operand_lists.append([Operand(type="imm")])
                    continue
                elif operand["class"] == "memory":
                    pre_indexed = "pre_indexed" in operand and operand["pre_indexed"]
                    post_indexed = "post_indexed" in operand and operand["post_indexed"]
                    operand_lists.append(
                        [Operand(type="mem", metadata={"pre_indexed": pre_indexed, "post_indexed": post_indexed})]
                    )
                    continue
                elif operand["class"] == "condition":
                    operand_lists.append([Operand(type="imm", width=4)])
                    continue
                # register case
                dec_operands: List[Operand] = []
                if "name" in operand:  # x86
                    dec_operands += copy.deepcopy(op_name_map[operand["name"]])
                elif "prefix" in operand:  # AArch64
                    if operand["prefix"] not in op_prefix_map:
                        print(f"unhandled prefix: {operand["prefix"]}")
                    else:
                        dec_operands = copy.deepcopy(op_prefix_map[operand["prefix"]])
                        if "width" in operand and operand["width"] == "*":
                            for dec in dec_operands:
                                dec.width = -1  # mark as any

                if "shape" in operand:
                    for dec in dec_operands:
                        dec.metadata["shape"] = operand["shape"]

                operand_lists.append(dec_operands)

                # handle additional mask
                if "mask" in operand and operand["mask"]:
                    # we currently dont use the mask operand type. TODO improve that
                    operand_lists.append([Operand(-1, "reg", 64)])

            # this creates a version for each possible width of generic "reg" operands
            for combination in itertools.product(*operand_lists):
                inst: Instruction = Instruction()
                inst.operands.extend(combination)
                inst.sourceName = name
                inst.asmName = name
                inst.source = "osaca"
                inst.latencies.append(Latency(None, None, entry["latency"], entry["latency"]))
                inst.throughputs.append(Throughput(entry["throughput"], entry["throughput"]))
                instructions.append(inst)

    # remove any duplicate entries (e.g. because two gprs or duplicate entries in input)
    id_set = set()
    result = []
    for inst in instructions:
        latencies = [f"{l.cyclesMin}" for l in inst.latencies]
        throughputs = [f"{tp.cyclesMin}" for tp in inst.throughputs]
        dec_operands = [f"{op.type}{op.width}{sorted(list(op.metadata))}" for op in inst.operands]
        id = f"{inst.sourceName}{sorted(set(latencies))}{sorted(set(throughputs))}{sorted(set(dec_operands))}"
        if id not in id_set:
            result.append(inst)
            id_set.add(id)

    # all read/write information we can get is that the last operand is written to on x86
    for inst in result:
        if len(inst.operands) > 0:
            if db["isa"] == "x64":
                inst.operands[-1].write = True
            if db["isa"] == "AArch64":
                inst.operands[0].write = True
    return result


if __name__ == "__main__":
    parse_osaca_database("analysis/reference-files/v2.yml")
