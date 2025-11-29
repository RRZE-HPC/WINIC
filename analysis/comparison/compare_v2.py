from analysis.globals import *
from analysis.parsing.parse_neoverse_opt_guide import parse_neoverse_opt_guide
import yaml
from matplotlib import pyplot as plt

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
    c_possible_val = 0
    c_impossible_val = 0
    for name in exact_matches:
        w_inst = w_inst_map.get(name)
        a_inst = a_inst_map.get(name)
        # latencies
        for lat in w_inst.latencies:
            if lat_possible_in(lat, a_inst):
                c_possible_val += 1
            else:
                c_impossible_val += 1
                print(f"inst: {w_inst} has impossible value {lat} when compared to {a_inst}")
        # throughputs
        for tp in w_inst.throughputs:
            if tp_possible_in(tp, a_inst):
                c_possible_val += 1
            else:
                c_impossible_val += 1
                print(f"inst: {w_inst} has impossible value {tp} when compared to {a_inst}")
    print(f"{c_possible_val=}")
    print(f"{c_impossible_val=}")
    fig, ax = plt.subplots()
    values = [c_possible_val, c_impossible_val]
    bars = ax.bar(
        ["values backed by opt guide", "values not possible according to opt guide"],
        values,
        # colors=["green", "red"],
        # autopct='%1.1f%%',
    )
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,   # X position (center of bar)
            bar.get_height(),                    # Y position (top of bar)
            f"{value}",                          # Text to display
            ha='center', va='bottom'             # Align text
        )
    # ax.text(ha='center')
    plt.title("Neoverse-V2: WINIC results vs V2 optimization guide")
    plt.legend()
    plt.savefig("WINIC_v2_optguide.png")


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
