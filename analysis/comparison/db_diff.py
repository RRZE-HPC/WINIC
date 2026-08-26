from analysis.comparison.helper import equal_tolerance

# from analysis.globals import *
from analysis.parsing.parse_winic import read_WINIC_db
from typing import Literal


# always increments c_changes
def _update_counters(old, new, c_changes, c_from_none, c_to_none):
    if old is None:
        c_from_none += 1
    if new is None:
        c_to_none += 1
    c_changes += 1
    return c_changes, c_from_none, c_to_none


def db_diff(database1, database2, mode: Literal["TP", "LAT", "BOTH"], verbose=False):
    db1 = read_WINIC_db(database1)
    db2 = read_WINIC_db(database2)
    verbose_output = ""
    c_changes = 0
    c_to_none = 0
    c_from_none = 0
    c_missing = 0
    c_new = 0

    for entry1 in db1:
        entry2 = None
        for e2 in db2:
            if e2["llvmName"] == entry1["llvmName"]:
                entry2 = e2
                break
        if entry2 == None:
            # only count as missing if entry1 has any value
            if entry1["throughput"] is not None or entry1["latency"] is not None:
                verbose_output += entry1["llvmName"] + " missing in new data\n"
                c_missing += 1
        else:
            # compare
            if mode == "TP" or mode == "BOTH":
                if not equal_tolerance(entry1["throughputMin"], entry2["throughputMin"], 0.1):
                    verbose_output += (
                        f"{entry1['llvmName']} tpLower {entry1['throughputMin']} -> {entry2['throughputMin']}\n"
                    )
                    c_changes, c_from_none, c_to_none = _update_counters(
                        entry1["throughputMin"], entry2["throughputMin"], c_changes, c_from_none, c_to_none
                    )
                if not equal_tolerance(entry1["throughputMax"], entry2["throughputMax"], 0.1):
                    verbose_output += (
                        f"{entry1['llvmName']} tpUpper {entry1['throughputMax']} -> {entry2['throughputMax']}\n"
                    )
                    c_changes, c_from_none, c_to_none = _update_counters(
                        entry1["throughputMax"], entry2["throughputMax"], c_changes, c_from_none, c_to_none
                    )

            # Latency
            if not (mode == "LAT" or mode == "BOTH"):
                continue
            lat_map2 = {(l["sourceOperand"], l["targetOperand"]): l for l in entry2["operandLatencies"]}
            for lat1 in entry1["operandLatencies"]:
                key = (lat1["sourceOperand"], lat1["targetOperand"])
                latString = f'{entry1["llvmName"]} ({lat1["sourceOperand"]} -> {lat1["targetOperand"]})'
                if key not in lat_map2:
                    if lat1["latencyMin"] is not None:
                        verbose_output += latString + "missing\n"
                        c_missing += 1
                else:
                    lat1_min = lat1["latencyMin"]
                    lat2_min = lat_map2[key]["latencyMin"]
                    lat1_max = lat1["latencyMax"]
                    lat2_max = lat_map2[key]["latencyMax"]
                    if not equal_tolerance(lat1_min, lat2_min, 0.1):
                        verbose_output += f"{latString} cyclesMin: {lat1_min} -> {lat2_min}\n"
                        c_changes, c_from_none, c_to_none = _update_counters(
                            lat1_min, lat2_min, c_changes, c_from_none, c_to_none
                        )
                    if not equal_tolerance(lat1_max, lat2_max, 0.1):
                        verbose_output += f"{latString} cyclesMax: {lat1_max} -> {lat2_max}\n"
                        c_changes, c_from_none, c_to_none = _update_counters(
                            lat1_max, lat2_max, c_changes, c_from_none, c_to_none
                        )

    # check for new entries
    for entry2 in db2:
        # only count as new if entry2 has any value
        if entry2["throughput"] is None and entry2["latency"] is None:
            continue
        entry1 = None
        for e1 in db1:
            if e1["llvmName"] == entry2["llvmName"]:
                entry1 = e1
                break
        if entry1 == None:
            verbose_output += entry2["llvmName"] + " added in new data\n"
            c_new += 1

    print(f"{c_changes} entries changed")
    print(f"{c_from_none} were None but have a value now")
    print(f"{c_to_none} had a value before but are None now")
    print(f"{c_missing} entries missing in new data")
    print(f"{c_new} new entries in new data")
    if verbose:
        print(verbose_output)
