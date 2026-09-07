from analysis.globals import *
from analysis.comparison.helper import *
from analysis.parsing.parse_neoverse_opt_guide import parse_neoverse_opt_guide
from analysis.parsing.parse_winic import read_WINIC_db, parse_WINIC_instruction

# this does not use additional LLVM information as the opt guide does not provide enough info per instruction anyway


def compare_winic_v2(database, mode, verbose: bool = False):
    db = read_WINIC_db(database)

    # parse neoverse opt guide instructions
    o_instructions: List[Instruction] = parse_neoverse_opt_guide()
    # SVE, asm: fdiv z0.d, p0/m, z1.d, z2.d, Z-register, LLVM: _D ARM: Floating point divide, F16
    # ASIMD, asm:    V-register, LLVM:  ARM: ASIMD
    # Scalar, asm: fdiv	d0, d1, d2, d-register, LLVM: FDIVDrr ARM: FP divide, H-form

    # load winic instructions
    w_instructions: List[Instruction] = []
    for db_entry in db:
        inst = parse_WINIC_instruction(db_entry, "AArch64")
        if inst is not None:
            inst.metadata["pre_indexed_mem"] = False
            inst.metadata["post_indexed_mem"] = False

            # move pre/post indexing information from operands to instruction metadata as opt guide does not have operands
            for op in inst.operands:
                if op.metadata.get("pre_indexed", 0):
                    inst.metadata["pre_indexed_mem"] = True
                if op.metadata.get("post_indexed", 0):
                    inst.metadata["post_indexed_mem"] = True
            inst.operands = []
            w_instructions.append(inst)
    # w_instructions: List[Instruction] = []
    # for db_entry in db:
    #     inst = Instruction()
    #     inst.asmName = db_entry["name"]
    #     inst.sourceName = db_entry["llvmName"]
    #     inst.throughputs.append(Throughput(db_entry["throughputMin"], db_entry["throughputMax"]))
    #     for lat in db_entry["operandLatencies"]:
    #         inst.latencies.append(Latency(None, None, lat["latencyMin"], lat["latencyMax"]))
    #     w_instructions.append(inst)
    print(len(w_instructions))
    compare_lists(w_instructions, o_instructions, mode, "loose", verbose)
