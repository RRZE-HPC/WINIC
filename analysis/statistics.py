from typing import List
from analysis.parsing.parse_winic import read_WINIC_db
from analysis.globals import Latency, is_range, covers


def count_ranges(database, pr: bool = False):
    # parse database
    db = read_WINIC_db(database)
    tp_range_c = 0
    tp_exact_c = 0
    lat_range_c = 0
    lat_exact_c = 0
    instrs_with_range = []
    for db_entry in db:
        # m_instr = parse_WINIC_instruction(db_entry,"X86")
        if db_entry["throughputMin"] != None:
            if db_entry["throughputMin"] != db_entry["throughputMax"]:
                tp_range_c += 1
            else:
                tp_exact_c += 1

        for lat_entry in db_entry["operandLatencies"]:
            if lat_entry["latencyMin"] != None:
                if lat_entry["latencyMin"] != lat_entry["latencyMax"]:
                    lat_range_c += 1
                    instrs_with_range.append(db_entry["llvmName"])
                else:
                    lat_exact_c += 1

    total_tp_c = tp_exact_c + tp_range_c
    total_lat_c = lat_exact_c + lat_range_c
    tp_exact_perc = 100 * tp_exact_c / total_tp_c
    lat_exact_perc = 100 * lat_exact_c / total_lat_c

    if pr:
        print(instrs_with_range)
    print(f"{total_tp_c} total TP values")
    print(f"{tp_exact_c} ({tp_exact_perc:.2f}%) exact TP values")
    print(f"{tp_range_c} ({100-tp_exact_perc:.2f}%) TP ranges")
    print(f"{total_lat_c} total LAT values")
    print(f"{lat_exact_c} ({lat_exact_perc:.2f}%) exact LAT values")
    print(f"{lat_range_c} ({100-lat_exact_perc:.2f}%) LAT ranges")


def count_instr_different_latencies(database, pr: bool = False):

    db = read_WINIC_db(database)
    one_latency = []
    same_latencies = []
    different_latencies_range = []
    different_latencies = []
    total_lat_values = 0
    total_possible_lat_values = 0
    # Go through each instruction
    for db_entry in db:
        latencies = db_entry.get("operandLatencies", None)
        all_values: List[Latency] = []
        exact_values: List[Latency] = []
        ranges: List[Latency] = []

        # add latency values to set
        for lat_entry in latencies:
            total_possible_lat_values += 1
            min_val = lat_entry.get("latencyMin", None)
            max_val = lat_entry.get("latencyMax", None)
            lat = Latency(None, None, min_val, max_val)
            if min_val is not None and max_val is not None:
                all_values.append(lat)
                if is_range(lat):
                    ranges.append(lat)
                else:
                    exact_values.append(lat)
                total_lat_values += 1

        if len(all_values) == 0:
            continue
        elif len(all_values) == 1:
            one_latency.append(db_entry.get("llvmName", None))
        elif len(ranges) == 0:
            if len(set([e.cyclesMin for e in exact_values])) == 1:
                same_latencies.append(db_entry.get("llvmName", None))
            else:
                different_latencies.append(db_entry.get("llvmName", None))
        else:
            # check if all exact values overlap with each range
            if all(all(covers(r, e) for e in exact_values) for r in ranges):
                different_latencies_range.append(db_entry.get("llvmName", None))
            else:
                # there is a range that can not in reality be the same as the exact latency
                different_latencies.append(db_entry.get("llvmName", None))

    print(f"{len(one_latency)} instructions have only one latency value")
    print(f"{len(same_latencies)} instructions have multiple latencies but they have the same value")
    print(
        f"{len(different_latencies_range)} instructions might have different latency values, but the those are ranges"
    )
    print(f"{len(different_latencies)} instructions have different latency values")
    print(f"{total_lat_values} latency values overall")
    print(f"{total_possible_lat_values} latency values possible including ones WINIC did not measure")
    if pr:
        print(f"List of instructions with one latency: {one_latency}")
        print(f"List of instructions with multiple latencies but the same value: {same_latencies}")
        print(f"List of instructions with different latencies but a range: {different_latencies_range}")
        print(f"List of instructions with different latencies: {different_latencies}")


def plot_distribution(database):
    from matplotlib import pyplot as plt
    import numpy as np

    db = read_WINIC_db(database)
    tps = [entry["throughput"] for entry in db if entry["throughput"] is not None]
    # vals = [latEntry["latencyMin"] for entry in db for latEntry in entry["operandLatencies"] if latEntry["latencyMin"] is not None]
    lats = [entry["latency"] for entry in db if entry["latency"] is not None]

    ax: list[plt.Axes]
    fig, ax = plt.subplots(1, 2, figsize=(10, 5))
    ax[0].hist(lats, range=(0, 12), bins=100)
    latNotShown = len([l for l in lats if l > 12])
    ax[0].set_xlabel(f"Latency ({latNotShown} values out of range)")
    ax[0].set_xticks(np.arange(0, 12))
    ax[0].set_ylabel("Number of instructions")

    ax[1].hist(tps, range=(0, 4.5), bins=100)
    latNotShown = len([t for t in tps if t > 4.5])
    ax[1].set_xlabel(f"Reciprocal throughput ({latNotShown} values out of range)")
    ax[1].set_xticks(np.arange(0, 5, 0.5))
    # ax[1].label_outer()

    fig.suptitle("Distribution of overall latency and througput values (considering maximum sublatency)")
    plt.tight_layout()
    plt.savefig("analysis/distribution.png")
