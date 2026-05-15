from analysis.globals import *
from analysis.comparison.helper import *
from analysis.parsing.parse_zen4_sheet import parse_zen4_sheet
from analysis.parsing.parse_winic import parse_WINIC_instruction, read_WINIC_db

# Naming scheme: w_xxx winic data, o_xxx other sources data


def compare_winic_zen4_sheet(database, mode: Literal["TP", "LAT", "BOTH"], verbose: bool = False):
    db = read_WINIC_db(database)

    # parse instructions from zen4 csv
    o_instructions: List[Instruction] = parse_zen4_sheet()

    # load winic instructions
    w_instructions: List[Instruction] = []
    for db_entry in db:
        inst = parse_WINIC_instruction(db_entry, "X86")
        if inst is not None:
            inst.asmName = db_entry["name"]  # dont use llvm asm string
            w_instructions.append(inst)

    print(f"{len(w_instructions)=}")
    # remove instructions accessing memory
    temp = []
    for o_inst in o_instructions:
        if not any([op.type in "mem" for op in o_inst.operands]):
            temp.append(o_inst)
    o_instructions = temp
    print(f"{len(o_instructions)=}")

    compare_lists(w_instructions, o_instructions, mode, "loose", verbose)
