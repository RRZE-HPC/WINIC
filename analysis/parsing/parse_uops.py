from analysis.globals import *
from typing import List
import os
import xml.etree.ElementTree as ET


# --- uops parsing --- #
def _parse_uops_operand(op: ET.Element) -> Operand:
    from .helper import get_register_width

    index = int(op.attrib["idx"]) if "idx" in op.attrib else None
    type = op.attrib["type"] if "type" in op.attrib else None
    if index is None:
        return None
    if type not in ["reg", "imm", "flags"]:
        return None

    read = bool(int(op.attrib.get("r", "0")))
    write = bool(int(op.attrib.get("w", "0")))
    suppressed = bool(int(op.attrib.get("suppressed", "0")))

    if op.text == "0" or op.text == 1:
        return None  # ignore fixed immediates
    if op.text is not None:
        regList = op.text.split(",")
    elif type == "flags":
        regList = ["EFLAGS"]
    else:
        regList = []

    if len(regList) == 1:
        # for some reason fixed registers dont have a width in uops database :(
        width = get_register_width(regList[0])
    else:
        width = int(op.attrib["width"]) if "width" in op.attrib else None
    return Operand(index, type, width, read, write, suppressed, regList)


def _parse_uops_latency(lat: ET.Element) -> Latency:
    try:
        startOp = int(lat.attrib["start_op"])
        targetOp = int(lat.attrib["target_op"])
        if "cycles" in lat.attrib:
            cycles = int(lat.attrib["cycles"])
            return Latency(startOp, targetOp, cycles, cycles)
        if "min_cycles" in lat.attrib and "max_cycles" in lat.attrib:
            cycles_min = int(lat.attrib["min_cycles"])
            cycles_max = int(lat.attrib["max_cycles"])
            return Latency(startOp, targetOp, cycles_min, cycles_max)
        print('unreachable, uops entry has neither field "cycels" nor "min_cycles" and "max_cycles')
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
    except KeyError:
        return None
    uopsName = entry.attrib["string"] if "string" in entry.attrib else ""
    inst = Instruction("uops", uopsName, uops_asm, operands, [Throughput(throughput, throughput)], latencies)
    inst.metadata["roundc"] = bool(int(entry.attrib["roundc"])) if "roundc" in entry.attrib else False
    inst.metadata["zeroing"] = bool(int(entry.attrib["zeroing"])) if "zeroing" in entry.attrib else False
    inst.metadata["evex"] = bool(int(entry.attrib["evex"])) if "evex" in entry.attrib else False
    inst.metadata["avx512"] = "AVX512" in entry.attrib["extension"] if "extension" in entry.attrib else False
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
