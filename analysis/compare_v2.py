from .globals import *
from .parsing.parse_neoverse_opt_guide import parse_neoverse_opt_guide

import yaml

# this does not use additional LLVM information as the opt guide does not provide enough info per instruction anyway


def _same_name(name1: str, name2: str):
    name1.lower() == name2.lower()


def _normalize_winic_name(inst_name: str):
    # make lowercase, remove e.g. .16b
    return inst_name.lower().split(".")[0]


def compare_winic_v2(database, mode, out_file):
    with open(database, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db = yaml.safe_load(raw_content)

    # parse neoverse opt guide instructions
    a_instructions: List[Instruction] = parse_neoverse_opt_guide()

    # load winic instructions
    w_instructions: List[Instruction] = []
    for db_entry in db:
        inst = Instruction()
        inst.asmName = db_entry["name"]
        inst.throughputs.append(Throughput(db_entry["throughputMin"], db_entry["throughputMax"]))
        for lat in db_entry["operandLatencies"]:
            inst.latencies.append(Latency(None, None, lat["latencyMin"], lat["latencyMax"]))
        w_instructions.append(inst)

    a_inst_map = {}
    for a_inst in a_instructions:
        a_inst_map[a_inst.asmName.lower()] = a_inst

    # combine insts with same name while generating list
    # w_inst_map = {_normalize_winic(w_inst.asmName): inst for w_inst in w_instructions}
    w_inst_map: dict[str, Instruction] = {}
    for w_inst in w_instructions:
        norm_name = _normalize_winic_name(w_inst.asmName)
        if norm_name in w_inst_map.keys():
            w_inst_map[norm_name].latencies += w_inst.latencies
            w_inst_map[norm_name].throughputs += w_inst.throughputs
        else:
            w_inst_map[norm_name] = w_inst

    # remove duplicate TP/LAT values
    for inst in w_instructions:
        unique = []
        seen = set()
        for lat in inst.latencies:
            if (lat.cyclesMin, lat.cyclesMax) not in seen:
                seen.add((lat.cyclesMin, lat.cyclesMax))
                unique.append(lat)
        inst.latencies = unique

        unique = []
        seen = set()
        for lat in inst.throughputs:
            if (lat.cyclesMin, lat.cyclesMax) not in seen:
                seen.add((lat.cyclesMin, lat.cyclesMax))
                unique.append(lat)
        inst.throughputs = unique

    exact_matches = set()
    for w_name in w_inst_map.keys():
        if w_name.lower() in a_inst_map.keys():
            exact_matches.add(w_name)

    print(f"arm instructions: {len(a_inst_map)}")
    print(f"WINIC instructions: {len(w_inst_map)}")

    w_unmatched = set(w_inst_map).difference(exact_matches)
    a_unmatched = set(a_inst_map).difference(exact_matches)
    print(f"exact matches by name: {len(exact_matches)}")
    print(f"not matched WINIC: {len(w_unmatched)}")
    print(f"not matched arm: {len(a_unmatched)}")
    # print(f"{exact_matches=}")
    # print(f"{w_unmatched=}")
    # print(f"{a_unmatched=}")
