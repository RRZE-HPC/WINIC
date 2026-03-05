from analysis.globals import *
from analysis.comparison.helper import *
from analysis.parsing.parse_exegesis import parse_exegesis
import yaml


def compare_winic_exegesis(db_winic, db_exegesis, mode: Literal["TP", "LAT", "BOTH"], out_file):
    with open(db_winic, "r") as file:
        raw_content = file.read()
    db = yaml.safe_load(raw_content)

    o_instructions: List[Instruction] = combine_dbs([parse_exegesis(d) for d in db_exegesis])

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

    o_inst_map: dict[str, Instruction] = {}
    for o_inst in o_instructions:
        o_inst_map[o_inst.sourceName] = o_inst

    w_inst_map: dict[str, Instruction] = {}
    for w_inst in w_instructions:
        w_inst_map[w_inst.sourceName] = w_inst

    exact_matches = set()
    for w_name in w_inst_map.keys():
        if w_name in o_inst_map.keys():
            exact_matches.add(w_name)

    print(f"exegesis instructions: {len(o_inst_map)}")
    print(f"WINIC instructions: {len(w_inst_map)}")

    w_unmatched = set(w_inst_map).difference(exact_matches)
    o_unmatched = set(o_inst_map).difference(exact_matches)
    print(f"exact matches by LLVM name: {len(exact_matches)}")
    print(f"{len(o_unmatched)} exegesis entrys not present in winic output: \n {sorted(o_unmatched)}")
    print(f"{len(w_unmatched)} winic entrys not present in exegesis output: \n {sorted(w_unmatched)}")

    counters: CompareCounters = CompareCounters()
    for name in exact_matches:
        p = False
        if w_inst.sourceName == "abc":
            print(w_inst)
            print(o_inst)
            p = True
        w_inst = w_inst_map.get(name)
        o_inst = o_inst_map.get(name)
        counters = get_stats(w_inst, o_inst, counters, mode, p)

    # check total number of instruction with value
    c_lat_obtained = 0  # how many instructions have a latency value
    c_tp_obtained = 0
    for w_inst in w_instructions:
        if any([l for l in w_inst.latencies if l.cyclesMin != None]):
            c_lat_obtained += 1
        if any([tp for tp in w_inst.throughputs if tp.cyclesMin != None]):
            c_tp_obtained += 1

    print(f"{c_lat_obtained=}")
    print(f"{c_tp_obtained=}\n")
    if len(exact_matches) != 0:
        print(f"\t{counters.c_lat_full=}, {counters.c_lat_full*100/len(exact_matches):.2f}%")
        print(f"\t{counters.c_lat_partial=}, {counters.c_lat_partial*100/len(exact_matches):.2f}%")
        print(f"\t{counters.c_lat_no=}, {counters.c_lat_no*100/len(exact_matches):.2f}%\n")
        print(f"\t{counters.c_tp_full=}, {counters.c_tp_full*100/len(exact_matches):.2f}%")
        print(f"\t{counters.c_tp_partial=}, {counters.c_tp_partial*100/len(exact_matches):.2f}%")
        print(f"\t{counters.c_tp_no=}, {counters.c_tp_no*100/len(exact_matches):.2f}%")
