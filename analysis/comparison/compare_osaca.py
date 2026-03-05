from pprint import pprint
from analysis.globals import *
from analysis.comparison.helper import *
from analysis.parsing.parse_osaca import parse_osaca_database
from analysis.parsing.parse_winic import parse_WINIC_instruction
import yaml
import itertools

# Naming scheme: w_xxx winic data, o_xxx other sources data


def _normalize_winic_name(inst_name: str):
    # make lowercase, remove e.g. .16b
    return inst_name.upper().split(".")[0]


# returns a similarity score for two operands. 0 means not the same,
# 1 is same but some register has universal (-1) width, 2 means exact match
# WARNING: O(n!) algorithm, don't use with large operand lists
def _operand_similarity(operands1: List[Operand], operands2: List[Operand], debug=False):
    # remove implicit operands as they are not listed in the amd document
    operands1 = [o for o in operands1 if o.suppressed == False]
    operands2 = [o for o in operands2 if o.suppressed == False]
    if len(operands1) != len(operands2):
        return 0
    if debug:
        print(f"comparing {operands1} to {operands2}")
    # convert each operand to a string containing the information we want to compare
    # then make a set of those operand representations and check if the sets are equal
    op1 = [f"{op.type}+{op.width}{sorted(list(op.metadata.items()))}" for op in operands1]
    op2 = [f"{op.type}+{op.width}{sorted(list(op.metadata.items()))}" for op in operands2]
    if debug:
        print(f"{op1=} check: tight")
        print(f"{op2=} check: tight")
    if set(op1) == set(op2):
        if debug:
            print("strong match")
        return 2
    # to get score 1, operands with width -1 are allowed to match with operands that have a width specified.
    # This is sensible as the amd table has entries with generic operands called "reg" while the WINIC database is always specific
    # This is a very inefficient algorithm as im too stupid to write something faster but since operand lists are normally not longer than 3 its fine
    perm = itertools.permutations(operands1)
    for p in list(perm):
        # check if this permutation of op1 matches with op2
        match = True
        for o1, o2 in zip(p, operands2):
            if o1.type != o2.type:
                match = False
                break
            if o1.width != o2.width and -1 not in [o1.width, o2.width]:
                match = False
                break
        if match:
            if debug:
                print("weak match")
            return 1
    return 0


def compare_winic_osaca(db_winic, db_osaca, mode: Literal["TP", "LAT", "BOTH"], out_file):
    with open(db_winic, "r") as file:
        raw_content = file.read()
    db = yaml.safe_load(raw_content)

    # find osaca arch
    with open(db_osaca, "r") as f:
        raw_content = f.read().replace("\t", "    ")  # yaml does not like tabs
    osaca = yaml.safe_load(raw_content)
    arch = osaca["isa"]
    if arch == "x86":
        arch = "X86"  # match our case

    # load winic instructions
    w_instructions: List[Instruction] = []
    for db_entry in db:
        inst = parse_WINIC_instruction(db_entry, arch)
        if inst is not None:
            inst.asmName = db_entry["name"]  # dont use llvm asm string
            w_instructions.append(inst)
    print(f"{len(w_instructions)=}")

    # parse instructions from osaca db
    o_instructions: List[Instruction] = parse_osaca_database(db_osaca)

    # remove instructions accessing memory
    temp = []
    for o_inst in o_instructions:
        if not any([op.type in "mem" for op in o_inst.operands]):
            temp.append(o_inst)
    o_instructions = temp
    print(f"{len(o_instructions)=}")

    # group by name
    o_inst_map: dict[str, List[Instruction]] = {}
    for o_inst in o_instructions:
        map_name = o_inst.sourceName.upper()
        if map_name in o_inst_map.keys():
            o_inst_map[map_name].append(o_inst)
        else:
            o_inst_map[map_name] = [o_inst]

    print(f"{len(o_inst_map)=}")
    compare_lists(w_instructions, o_instructions, mode, "loose")
