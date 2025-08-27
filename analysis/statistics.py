from .parsing import *
import yaml


def count_ranges(database):
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
        if m_instr.throughput_lower != None:
            if m_instr.throughput_lower != m_instr.throughput_upper:
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
    c_has_value = 0
    c_different_value = 0
    # Go through each instruction
    for db_entry in db:
        m_instr = parse_WINIC_instruction(db_entry)
        latency_values = set()

        # add latency values to set
        for lat in m_instr.latencies:
            if lat.cyclesMin is not None:
                latency_values.add(lat.cyclesMin)

        # If we have at least two different latencies
        if len(latency_values) >= 1:
            c_has_value += 1
        if len(latency_values) >= 2:
            c_different_value += 1
            # print(f"Instruction with multiple latencies: {db_entry['llvmName']}")
            # print(f"Latencies: {latency_values}")

    print(f"{c_different_value} of {c_has_value} instructions have at least two different latency values")
