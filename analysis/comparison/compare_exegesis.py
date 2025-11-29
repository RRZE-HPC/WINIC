from analysis.globals import *
from analysis.parsing.parse_exegesis import parse_exegesis
import yaml


def compare_winic_exegesis(db_winic, db_exegesis, mode: Literal["TP", "LAT", "BOTH"], out_file):
    with open(db_winic, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db = yaml.safe_load(raw_content)

    e_instructions: List[Instruction] = parse_exegesis(db_exegesis)

    # load winic instructions
    w_instructions: List[Instruction] = []
    for db_entry in db:
        inst = Instruction(source="winic")
        inst.sourceName = db_entry["llvmName"]
        inst.asmName = db_entry["name"]
        inst.throughputs.append(Throughput(db_entry["throughputMin"], db_entry["throughputMax"]))
        for lat in db_entry["operandLatencies"]:
            inst.latencies.append(Latency(None, None, lat["latencyMin"], lat["latencyMax"]))
        w_instructions.append(inst)

    e_inst_map: dict[str, Instruction] = {}
    for e_inst in e_instructions:
        e_inst_map[e_inst.sourceName] = e_inst

    w_inst_map: dict[str, Instruction] = {}
    for w_inst in w_instructions:
        w_inst_map[w_inst.sourceName] = w_inst

    exact_matches = set()
    for w_name in w_inst_map.keys():
        if w_name in e_inst_map.keys():
            exact_matches.add(w_name)

    print(f"exegesis instructions: {len(e_inst_map)}")
    print(f"WINIC instructions: {len(w_inst_map)}")

    w_unmatched = set(w_inst_map).difference(exact_matches)
    e_unmatched = set(e_inst_map).difference(exact_matches)
    print(f"exact matches by LLVM name: {len(exact_matches)}")
    print(f"{len(e_unmatched)} exegesis entrys not present in winic output: \n {e_unmatched}")
    print(f"{len(w_unmatched)} winic entrys not present in exegesis output: \n {w_unmatched}")
    c_matching_val = 0
    c_no_matching_val = 0
    for name in exact_matches:
        w_inst = w_inst_map.get(name)
        e_inst = e_inst_map.get(name)
        # latency
        if mode in ["LAT", "BOTH"]:
            if len(e_inst.latencies) != 0 and lat_possible_in(e_inst.latencies[0], w_inst):
                c_matching_val += 1
            else:
                c_no_matching_val += 1
                print(f"inst: {e_inst.sourceName}: exegesis value {e_inst.latencies[0]} not in {w_inst}")
        # throughput
        if mode in ["TP", "BOTH"]:
            if len(e_inst.throughputs) != 0 and tp_possible_in(e_inst.throughputs[0], w_inst):
                c_matching_val += 1
            else:
                c_no_matching_val += 1
                print(f"inst: {e_inst.sourceName}: exegesis value {e_inst.throughputs[0]} not in {w_inst}")
    print(f"Exegesis values that correspond to at least one WINIC value:{c_matching_val=}")
    print(f"Exegesis values that do not correspond to any WINIC measurement: {c_no_matching_val=}")


# if the latency is a range, check that there is at least one value or range in ref_inst that allows any value in that range. (with a tolerance of 10%)
# this is the weakest condition possible to classify a value as "correct" assuming the reg_inst represents the truth
def lat_possible_in(lat: Latency, ref_inst: Instruction):
    if any(x is None for x in [lat, lat.cyclesMin, lat.cyclesMax]):
        return True
    for ref_lat in ref_inst.latencies:
        if any(x is None for x in [ref_lat, ref_lat.cyclesMin, ref_lat.cyclesMax]):
            continue
        if not lat.cyclesMax < ref_lat.cyclesMin * 0.9 or lat.cyclesMin > ref_lat.cyclesMax * 1.1:
            return True
    return False


def tp_possible_in(tp: Throughput, ref_inst: Instruction):
    if any(x is None for x in [tp, tp.cyclesMin, tp.cyclesMax]):
        return True
    for ref_tp in ref_inst.throughputs:
        if any(x is None for x in [ref_tp, ref_tp.cyclesMin, ref_tp.cyclesMax]):
            continue
        if not tp.cyclesMax < ref_tp.cyclesMin * 0.9 or tp.cyclesMin > ref_tp.cyclesMax * 1.1:
            return True
    return False
