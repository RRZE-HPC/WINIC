import yaml


def count_ranges(database):
    from .parsing.parse_winic import parse_WINIC_instruction

    # parse database
    with open(database, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db = yaml.safe_load(raw_content)
    tp_range_c = 0
    tp_exact_c = 0
    lat_range_c = 0
    lat_exact_c = 0
    for db_entry in db:
        m_instr = parse_WINIC_instruction(db_entry)
        if m_instr.throughputs[0].cyclesMin != None:
            if m_instr.throughputs[0].cyclesMin != m_instr.throughputs[0].cyclesMax:
                tp_range_c += 1
            else:
                tp_exact_c += 1

        for lat_entry in m_instr.latencies:
            if lat_entry.cyclesMin != None:
                if lat_entry.cyclesMin != lat_entry.cyclesMax:
                    lat_range_c += 1
                else:
                    lat_exact_c += 1

    total_tp_c = tp_exact_c + tp_range_c
    total_lat_c = lat_exact_c + lat_range_c
    tp_exact_perc = 100 * tp_exact_c / total_tp_c
    lat_exact_perc = 100 * lat_exact_c / total_lat_c

    print(f"{total_tp_c} total TP values")
    print(f"{tp_exact_c} ({tp_exact_perc:.2f}%) exact TP values")
    print(f"{tp_range_c} ({100-tp_exact_perc:.2f}%) TP ranges")
    print(f"{total_lat_c} total LAT values")
    print(f"{lat_exact_c} ({lat_exact_perc:.2f}%) exact LAT values")
    print(f"{lat_range_c} ({100-lat_exact_perc:.2f}%) LAT ranges")
    # print(f"{lat_range_counter=}")
    # print(f"{lat_exact_counter=}")
    # print(f"proportion TP ranges: {tp_range_counter/(tp_range_counter+tp_exact_counter):.2f}")
    # print(f"proportion LAT ranges: {lat_range_counter/(lat_range_counter+lat_exact_counter):.2f}")


def count_instr_different_sublatencies(database):
    with open(database, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db = yaml.safe_load(raw_content)
    different_latencies_ranges = []
    different_latencies_exact = []
    # Go through each instruction
    for db_entry in db:
        latencies = db_entry.get("operandLatencies", None)
        min_values = set()
        has_range = False

        # add latency values to set
        for lat in latencies:
            min = lat.get("latencyMin", None)
            max = lat.get("latencyMax", None)
            if min is not None and max is not None:
                min_values.add(min)
                if min != max:
                    has_range = True

        # Check if there are at least two different latency values
        if len(min_values) >= 2:
            # distinguish instructions with ranges and ones without
            if has_range:
                different_latencies_ranges.append(db_entry.get("llvmName", None))
            else:
                different_latencies_exact.append(db_entry.get("llvmName", None))

    print(
        f"{len(different_latencies_ranges)} instructions have at least two different latency values, but also have some range as result"
    )
    print(
        f"{len(different_latencies_exact)} instructions have at least two different latency values, and have only exact values"
    )
    print(f"List of instructions with different sub-latencies and ranges: {different_latencies_ranges}")
    print(f"List of instructions with different sub-latencies and no ranges: {different_latencies_exact}")
