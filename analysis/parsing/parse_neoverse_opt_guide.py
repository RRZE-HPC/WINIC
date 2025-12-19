from analysis.globals import *
import pdfplumber
from typing import List
from dataclasses import replace
import pickle


# parses strings like "3" or "1/12" to floats
def _parse_fraction_or_value(input: str) -> float:
    if "/" in input:  # manual gives values as fractions :(
        fraction = input.split("/")
        return float(fraction[0]) / float(fraction[1])
    elif input == "½":  # this is incredibly stupid @Arm
        return 0.5
    else:
        return float(input)


@dataclass
class TableEntry:
    instGroup: str
    name: str
    execLat: str
    execTP: str
    pipelines: str
    notes: str


def _extract_from_pdf():
    manual_path = "analysis/reference-files/arm_neoverse_v2_software_optimization_guide_109898_0300_01_en.pdf"
    table_entries: List[TableEntry] = []
    with pdfplumber.open(manual_path) as pdf:
        table_settings = {
            "vertical_strategy": "lines",
            "horizontal_strategy": "lines",
            "snap_tolerance": 3,
            "join_tolerance": 3,
            "edge_min_length": 50,
        }
        tables = [page.extract_tables(table_settings=table_settings) for page in pdf.pages[14:54]]
        table_lines = [
            line
            for page in tables
            if page is not None
            for table in page
            if table is not None
            for line in table
            if line[0] != "Instruction Group" and line[1] != "Instructions"
        ]

        # remove duplicate lines
        temp_lines = []
        seen = set()
        for line in table_lines:
            tuple_line = tuple(line)
            if tuple_line not in seen:
                temp_lines.append(line)
                seen.add(tuple_line)
        table_lines = temp_lines

        # print(table_lines)
        for line in table_lines:
            if len(line) == 6:  # ignore tables that dont have instructions in them
                table_entries.append(TableEntry(line[0], line[1], line[2], line[3], line[4], line[5]))
    return table_entries


def parse_neoverse_opt_guide() -> List[Instruction]:
    if os.path.exists("cache.pkl"):
        with open("cache.pkl", "rb") as f:
            try:
                table_entries = pickle.load(f)
            except Exception:
                table_entries = _extract_from_pdf()
                with open("cache.pkl", "wb") as f2:
                    pickle.dump(table_entries, f2, protocol=pickle.HIGHEST_PROTOCOL)
    else:
        table_entries = _extract_from_pdf()
        with open("cache.pkl", "wb") as f2:
            pickle.dump(table_entries, f2, protocol=pickle.HIGHEST_PROTOCOL)

    # propagate instruction group field
    lastEntry: TableEntry = table_entries[0]
    for entry in table_entries[1:]:
        if entry.instGroup in ["", None]:
            entry.instGroup = lastEntry.instGroup
        lastEntry = entry

    # some lines have "INST1, INST2" -> make them separate lines
    unique_entries = [
        replace(entry, name=name.strip())
        for entry in table_entries
        for name in (entry.name or "").split(",")
        if name.strip() != "" and name.strip() != "-"  # filter empty rows and rows with "-"
    ]

    # some instructions have INST(2) -> separate them into INST and INST2
    temp: List[TableEntry] = []
    for entry in unique_entries:
        if "(2)" in entry.name:
            base = entry.name.split("(")[0]
            temp.append(replace(entry, name=base))
            temp.append(replace(entry, name=base + "2"))
        else:
            temp.append(entry)
    unique_entries = temp

    instructions: List[Instruction] = []
    lastInstruction: Instruction = Instruction()
    for entry in unique_entries:
        inst: Instruction = Instruction()
        if entry.name is None:
            print(f"look at {entry}")
            continue
        inst.source = "docs"
        inst.asmName = entry.name

        # if table cell has instructions on multiple lines, parser generates lines without values for all but the first one
        values_missing = [value in [None, ""] for value in [entry.execLat, entry.execTP]]
        if not any(values_missing):
            lat_string = entry.execLat
            if "(" in lat_string:
                # case e.g. "3(1)"
                lat1 = lat_string[0 : lat_string.find("(")].strip()
                lat2 = lat_string[lat_string.find("(") + 1 : lat_string.find(")")]
                inst.latencies.append(Latency(None, None, lat1, lat1))
                inst.latencies.append(Latency(None, None, lat2, lat2))
            elif "," in lat_string:
                # case e.g. "1, 2"
                lat1 = lat_string.split(",")[0].strip()
                lat2 = lat_string.split(",")[1].strip()
                inst.latencies.append(Latency(None, None, lat1, lat1))
                inst.latencies.append(Latency(None, None, lat2, lat2))
            else:
                # cases e.g. "7 to 12" and "7"
                # the following works no matter if the split produces 2 or 1 values
                range_or_val = lat_string.split("to")
                lower_val = _parse_fraction_or_value(range_or_val[0])
                upper_val = _parse_fraction_or_value(range_or_val[-1])
                inst.latencies.append(Latency(None, None, lower_val, upper_val))

            tp_string = entry.execTP
            if "(" in tp_string:
                tp1 = int(tp_string[0 : tp_string.find("(")].strip())
                tp2 = int(tp_string[tp_string.find("(") + 1 : tp_string.find(")")])
                inst.throughputs.append(Throughput(1 / tp1, 1 / tp1))
                inst.throughputs.append(Throughput(1 / tp2, 1 / tp2))
            elif "," in tp_string:
                tp1 = float(tp_string.split(",")[0].strip())
                tp2 = float(tp_string.split(",")[1].strip())
                inst.throughputs.append(Throughput(1 / tp1, 1 / tp1))
                inst.throughputs.append(Throughput(1 / tp2, 1 / tp2))
            else:
                range_or_val = tp_string.split("to")
                lower_val = _parse_fraction_or_value(range_or_val[0])
                upper_val = _parse_fraction_or_value(range_or_val[-1])
                # talke reciprocal TP -> upper bound gets lower bound
                inst.throughputs.append(Throughput(1 / upper_val, 1 / lower_val))

        elif all(values_missing):
            # also a common case, take values of last instruction
            inst.latencies = lastInstruction.latencies
            inst.throughputs = lastInstruction.throughputs
        elif any(values_missing):
            # this is unusual, we should investigate
            print(f"unusual line: {entry}")

        instructions.append(inst)
        lastInstruction = inst

    # name_count = {}
    # for inst in instructions:
    #     if inst.asmName in name_count.keys():
    #         name_count[inst.asmName] += 1
    #     else:
    #         name_count[inst.asmName] = 1

    # merge instructions with same name (add throughput values to one representative)
    unified: dict[str, Instruction] = dict()
    for inst in instructions:
        if inst.asmName in unified.keys():
            unified[inst.asmName].latencies += inst.latencies
            unified[inst.asmName].throughputs += inst.throughputs
        else:
            unified[inst.asmName] = inst
    instructions = list(unified.values())

    # remove duplicate TP/LAT values
    for inst in instructions:
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

    # print(instructions)
    return instructions
