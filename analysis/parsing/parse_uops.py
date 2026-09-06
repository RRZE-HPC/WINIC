from analysis.globals import *
from typing import List
import os
import xml.etree.ElementTree as ET


# --- uops parsing --- #
def _parse_uops_operand(op: ET.Element) -> Operand:
    from .helper import get_x86_register_width

    index = int(op.attrib["idx"]) if "idx" in op.attrib else None
    type = op.attrib["type"] if "type" in op.attrib else None
    if index is None:
        return None
    if type not in ["reg", "imm", "flags", "mem"]:
        return None

    read = bool(int(op.attrib.get("r", "0")))
    write = bool(int(op.attrib.get("w", "0")))
    suppressed = bool(int(op.attrib.get("suppressed", "0")))

    if op.text == "0" or op.text == "1":
        return None  # ignore fixed immediates
    if op.text is not None:
        regList = op.text.split(",")
    elif type == "flags":
        regList = ["EFLAGS"]
    else:
        regList = []

    # uops register width is sometimes weird/wrong, see VPBROADCASTD (XMM, XMM)
    # if possible use our own decoder to get the width, otherwise fallback to uops
    width = get_x86_register_width(regList[0]) if len(regList) > 0 else None
    if width is None:
        width = int(op.attrib["width"]) if "width" in op.attrib else None

    return Operand(index, type, width, read, write, suppressed, regList)


def _parse_uops_latency(lat: ET.Element) -> Latency:
    try:
        startOp = int(lat.attrib["start_op"])
        targetOp = int(lat.attrib["target_op"])
        if "cycles" in lat.attrib:
            cycles = int(lat.attrib["cycles"])
            upper_bound = "cycles_is_upper_bound" in lat.attrib and lat.attrib["cycles_is_upper_bound"] == "1"
            return Latency(startOp, targetOp, 1 if upper_bound else cycles, cycles)
        if "cycles_mem" in lat.attrib:
            # we only consider the memory latency and ignore the base/index registers etc.
            cycles = int(lat.attrib["cycles_mem"])
            upper_bound = "cycles_mem_is_upper_bound" in lat.attrib and lat.attrib["cycles_mem_is_upper_bound"] == "1"
            return Latency(startOp, targetOp, 1 if upper_bound else cycles, cycles)
        if "min_cycles" in lat.attrib and "max_cycles" in lat.attrib:
            return Latency(startOp, targetOp, int(lat.attrib["min_cycles"]), int(lat.attrib["max_cycles"]))

        # uops entry has neither field "cycles" nor "cycles_mem" nor "min_cycles" and "max_cycles",
        # this happens with latency measurements with where only values for base/index registers are present
        return None
    except KeyError:
        # happens e.g. on latency values regarding memory
        return None


def _parse_uops_instruction(entry: ET.Element, arch: str):
    if (
        (u_arch := entry.find(f"architecture[@name='{arch}']")) is None
        or (u_operands := entry.findall("operand")) is None
        or (u_m := u_arch.find("measurement")) is None
        or (u_lat := u_m.findall("latency")) is None
    ):
        return None
    operands = [_parse_uops_operand(op) for op in u_operands]
    if None in operands:
        return None  # cannot parse all operands
    latencies = [x for x in [_parse_uops_latency(lat) for lat in u_lat] if x is not None]
    try:
        throughput = float(u_m.attrib["TP_loop"])
        uops_asm = entry.attrib["asm"]
        # there are things like {load} CMP in uops, remove those
        start, end = uops_asm.find("{"), uops_asm.find("}")
        uops_asm = uops_asm.removeprefix(uops_asm[start : end + 1]).strip()
        uops_asm = uops_asm.removeprefix("LOCK").strip()
    except KeyError:
        return None
    uopsName = entry.attrib["string"] if "string" in entry.attrib else ""
    inst = Instruction("uops", uopsName, uops_asm, operands, [Throughput(throughput, throughput)], latencies)
    inst.metadata["roundc"] = bool(int(entry.attrib["roundc"])) if "roundc" in entry.attrib else False
    inst.metadata["zeroing"] = bool(int(entry.attrib["zeroing"])) if "zeroing" in entry.attrib else False
    inst.metadata["evex"] = bool(int(entry.attrib["evex"])) if "evex" in entry.attrib else False
    inst.metadata["avx512"] = "AVX512" in entry.attrib["extension"] if "extension" in entry.attrib else False
    inst.metadata["locked"] = bool(int(entry.attrib["locked"])) if "locked" in entry.attrib else False
    return inst


def parse_uops_database(arch: str) -> List[Instruction]:
    root = ET.parse(os.path.join(script_dir, "reference-files", "uops.xml"))
    u_instrNodes = root.findall(f".//instruction")
    instructions = []
    for entry in u_instrNodes:
        inst = _parse_uops_instruction(entry, arch)
        if inst is not None:
            instructions.append(inst)
    return instructions
