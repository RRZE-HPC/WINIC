from .globals import *
from typing import List, Literal
from pprint import pprint
import os
import yaml


def is_same_asm_name(llvm_asm: str, uops_asm: str):
    debug(f"{llvm_asm}, {uops_asm}")
    # llvm names have those "AsmString": "{cbtw|cbw}", select second variant
    try:
        if llvm_asm[0] == "{":
            llvm_asm = llvm_asm[max(llvm_asm.find("|"), llvm_asm.find("{")) : llvm_asm.find("}")]
        else:
            indices = (
                llvm_asm.find(" "),
                llvm_asm.find("|"),
                llvm_asm.find("{"),
                llvm_asm.find("}"),
                llvm_asm.find("\t"),
            )

            positiveIndices = [i for i in indices if i != -1]
            if positiveIndices and min(positiveIndices) != -1:
                llvm_asm = llvm_asm[0 : min(positiveIndices)]

        llvm_asm = llvm_asm.upper()
    except RuntimeError as e:
        print("isSameAsmName: Error encountered")
        return False

    # there are things like {load} CMP in uops
    start = uops_asm.find("{")
    end = uops_asm.find("}")
    uops_asm = uops_asm.removeprefix(uops_asm[start : end + 1]).strip()
    if llvm_asm != uops_asm:
        return False
    return True


# set debug true, dbg instr. to LLVM Name and set uops name to check why two instrucions were not matched
# debug = True
dbgInstruction = ""
dbgUopsInstructionString = ""
# things that should match
# VFMADD132PDZrb VFMADD132PD_ER (ZMM, ZMM, ZMM)
# ADC16ri ADC (R16, I16)
# VSCALEFSSZrr: VSCALEFSS (XMM, XMM, XMM)


def is_same(uopsInst: Instruction, LLVMInst: Instruction):
    global dbgInstruction
    if dbgInstruction != "" and dbgUopsInstructionString not in uopsInst.uopsName:
        return False
    if not is_same_asm_name(LLVMInst.asmName, uopsInst.asmName):
        if dbgInstruction != "":
            print("name")
            pprint(uopsInst, compact=True)
            pprint(LLVMInst, compact=True)
        return False
    if len(uopsInst.operands) != len(LLVMInst.operands):
        if dbgInstruction != "":
            print("numOps")
            pprint(uopsInst, compact=True)
            pprint(LLVMInst, compact=True)
        return False
    if uopsInst.roundc != LLVMInst.roundc:
        if dbgInstruction != "":
            print("roundc")
            pprint(uopsInst, compact=True)
            pprint(LLVMInst, compact=True)
        return False
    # match operands
    llvmOps = LLVMInst.operands.copy()
    for op in uopsInst.operands:
        for lOp in llvmOps:
            if op == lOp:
                llvmOps.remove(lOp)
                break
    if len(llvmOps) != 0:
        if dbgInstruction != "":
            print("not all operands covered")
            pprint(uopsInst, compact=True)
            pprint(LLVMInst, compact=True)
        return False
    return True


# compare the results with uops data.
def compare(database, type: Literal["lat", "tp"], arch: str) -> Counters:
    # parse measured instructions
    from .parsing import parse_uops_database, parse_WINIC_instruction

    with open(database, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db = yaml.safe_load(raw_content)
    uops_instructions = parse_uops_database(arch)

    c = Counters(0, 0, 0, 0, 0, 0, 0, 0, 0)
    outputLines = []
    if type == "tp":
        for db_entry in db:
            c.dbEntryC += 1
            progress_bar(c.dbEntryC, len(db))
            # if c.dbProgressC % 1000 == 0:
            #     print(c.dbProgressC)
            if dbgInstruction != "" and db_entry["llvmName"] != dbgInstruction:
                continue

            m_cycles = db_entry["throughputMin"]
            if m_cycles == None:
                c.dbEmptyValueC += 1
                continue
            m_instr = parse_WINIC_instruction(db_entry)
            if m_instr is None:
                c.internalErrorC += 1
                continue
            llvm_name = db_entry["llvmName"]

            m_cycles = m_instr.throughput_lower
            # find uops instsruction
            u_matches: List[Instruction] = []
            for u_instr in uops_instructions:
                if is_same(u_instr, m_instr):
                    u_matches.append(u_instr)

            if len(u_matches) == 0:
                outputLines.append(f"{llvm_name}: no match, classify: noMatch\n")
                c.noMatchC += 1
            else:
                # one or multiple matches
                data_match = [
                    0.92 * m_instr.throughput_lower <= u_instr.throughput_lower <= 1.09 * m_instr.throughput_upper
                    for u_instr in u_matches
                ]
                debug([(u_inst.throughput_lower, m_cycles) for u_inst in u_matches])
                debug(data_match)

                if False in data_match:
                    outputLines.append(
                        f"{llvm_name}: {u_matches[0].uopsName} uops: {u_matches[0].throughput_lower}, WINIC: {m_cycles}, classify: differentVal(s)\n"
                    )
                    if len(data_match) == 1:
                        c.uniqueMatchDiffValueC += 1
                    else:
                        c.multiMatchDiffValueC += 1

                else:
                    outputLines.append(
                        f"{llvm_name}: {u_matches[0].uopsName} uops: {u_matches[0].throughput_lower}, WINIC: {m_cycles}, classify: matchingVal(s)\n"
                    )
                    if len(data_match) == 1:
                        c.uniqueMatchSameValueC += 1
                    else:
                        c.multiMatchSameValueC += 1

        with open(os.path.join(script_dir, "compareTP.log"), "w") as out_file:
            out_file.writelines(outputLines)

    if type == "lat":
        c_progress = 0
        for db_entry in db:
            llvm_name = db_entry["llvmName"]
            m_instr = parse_WINIC_instruction(db_entry)
            if m_instr is None:
                c.internalErrorC += 1
                continue

            c.dbEntryC += len(m_instr.latencies)
            c_progress += 1
            progress_bar(c_progress, len(db))
            # find uops inststruction
            u_matches: List[Instruction] = []
            for u_instr in uops_instructions:
                if is_same(u_instr, m_instr):
                    u_matches.append(u_instr)

            if len(u_matches) == 0:
                outputLines.append(f"{llvm_name}: no match, classify: noMatch\n")
                for lat in m_instr.latencies:
                    if lat.cyclesMin != None:
                        c.noMatchC += 1
                    else:
                        c.dbEmptyValueC += 1
                continue

            # if u_instr.uopsName != "VDIVPD (XMM, K, XMM, XMM)":
            #     continue
            # one or multiple matches
            for m_lat in m_instr.latencies:
                if m_lat.cyclesMin == None:
                    c.dbEmptyValueC += 1
                    continue
                data_match = []
                for u_instr in u_matches:
                    # find the corresponding latency value in the uops instruction
                    # first get the actual operands
                    try:
                        m_src_op = next(op for op in m_instr.operands if op.index == m_lat.startOpIndex)
                        m_dst_op = next(op for op in m_instr.operands if op.index == m_lat.targetOpIndex)
                    except StopIteration:
                        print("fatal error, latency result references an non-existing operand (unreachable)")
                        pprint(m_instr)
                        exit(1)

                    # get all uops operands that could correspond to the current winic ones
                    u_src_candidates = [op for op in u_instr.operands if op == m_src_op]
                    u_dst_candidates = [op for op in u_instr.operands if op == m_dst_op]
                    # select the correct candidate
                    # if there are multiple operands that fulfill the == constraint TODO currently just fail
                    if len(u_src_candidates) == 0 or len(u_dst_candidates) == 0:
                        # this should never happen, unless the instructions were matched incorrectly
                        print("alarm")
                        exit(1)
                    if len(u_src_candidates) > 1:
                        # if there are multiple operands with same read/write/register combination,
                        # we assume they are in the same order for both uops and winic database
                        # therefore this is written in a way so it doesn't matter which indices the operands have, only that the order is right
                        # all the operands with same properties from winic
                        m_src_candidates = [op for op in m_instr.operands if op == m_src_op]
                        # the index of the current operand in m_src_candidates
                        m_index_in_list = next(i for i, op in enumerate(m_src_candidates) if op.index == m_src_op.index)
                        # take the element at the same index from u_src_candidates
                        u_src_op = u_src_candidates[m_index_in_list]
                    else:
                        u_src_op = u_src_candidates[0]
                    if len(u_dst_candidates) > 1:
                        m_dst_candidates = [op for op in m_instr.operands if op == m_dst_op]
                        m_index_in_list = next(i for i, op in enumerate(m_dst_candidates) if op.index == m_dst_op.index)
                        u_dst_op = u_dst_candidates[m_index_in_list]
                    else:
                        u_dst_op = u_dst_candidates[0]

                    # extract the uops latency result
                    try:
                        u_lat = next(
                            lat
                            for lat in u_instr.latencies
                            if lat.startOpIndex == u_src_op.index and lat.targetOpIndex == u_dst_op.index
                        )
                    except StopIteration:
                        continue
                    if m_lat.cyclesMin <= u_lat.cyclesMin and u_lat.cyclesMin <= m_lat.cyclesMax:
                        data_match.append(True)
                        outputLines.append(
                            f"{llvm_name}: {u_instr.uopsName} {u_lat.startOpIndex} -> {u_lat.targetOpIndex} uops: {u_lat.cyclesMin}, WINIC: {m_lat.cyclesMin}-{m_lat.cyclesMax}, classify: sameVal\n"
                        )
                    else:
                        data_match.append(False)
                        outputLines.append(
                            f"{llvm_name}: {u_instr.uopsName} {u_lat.startOpIndex} -> {u_lat.targetOpIndex} uops: {u_lat.cyclesMin}, WINIC: {m_lat.cyclesMin}-{m_lat.cyclesMax}, classify: differentVal\n"
                        )
                if len(data_match) == 0:
                    c.noUopsDataC += 1
                elif False in data_match:
                    if len(data_match) == 1:
                        c.uniqueMatchDiffValueC += 1
                    else:
                        c.multiMatchDiffValueC += 1

                elif all(data_match):
                    if len(data_match) == 1:
                        c.uniqueMatchSameValueC += 1
                    else:
                        c.multiMatchSameValueC += 1

        with open(os.path.join(script_dir, "compareLAT.log"), "w") as out_file:
            out_file.writelines(outputLines)

    print(f"{c.dbEntryC} total database entries")
    print(f"{c.dbEntryC-c.dbEmptyValueC} entries have values")
    print(f"{c.uniqueMatchSameValueC} values match with exactly one uops instruction")
    print(f"{c.multiMatchSameValueC} values match with multiple uops instructions which all have the same value")
    print(f"{c.multiMatchDiffValueC} values were matched with multiple uops instructions with different values")
    print(f"{c.uniqueMatchDiffValueC} values don't match with uops data")
    print(f"{c.noMatchC} values could not be matched with an instruction from uops")
    print(f"{c.internalErrorC} internal errors occurred")
    print(f"{c.noUopsDataC} values were matched but uops has no data")
    total_matching = c.uniqueMatchSameValueC + c.multiMatchSameValueC
    total_non_matching = c.uniqueMatchDiffValueC + c.multiMatchDiffValueC
    print(
        f"{(total_matching)*100/(total_matching+total_non_matching):.2f}% of values are the same (excluding missing matches)"
    )
    return c


def equal_tolerance(val1, val2):
    if val1 == val2:
        return True
    if val1 == None or val2 == None:
        return False
    return val1 * 0.9 < val2 < val1 * 1.1


# always increments c_changes
def update_counters(old, new, c_changes, c_from_none, c_to_none):
    if old is None:
        c_from_none += 1
    if new is None:
        c_to_none += 1
    c_changes += 1
    return c_changes, c_from_none, c_to_none


def db_diff(database1, database2, mode: Literal["TP", "LAT", "BOTH"], output_path=""):
    with open(database1, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db1 = yaml.safe_load(raw_content)
    with open(database2, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces
    db2 = yaml.safe_load(raw_content)
    output = ""
    c_changes = 0
    c_to_none = 0
    c_from_none = 0
    c_missing = 0

    for entry1 in db1:
        entry2 = None
        for e2 in db2:
            if e2["llvmName"] == entry1["llvmName"]:
                if e2["llvmName"] == "VAND_VX":
                    print("VAND_VX")
                entry2 = e2
                break
        if entry2 == None:
            output += entry1["llvmName"] + " missing in new data\n"
            c_missing += 1
        else:
            # compare
            if mode == "TP" or mode == "BOTH":
                if not equal_tolerance(entry1["throughputMin"], entry2["throughputMin"]):
                    output += f"{entry1["llvmName"]} tpLower {entry1["throughputMin"]} -> {entry2["throughputMin"]}\n"
                    c_changes, c_from_none, c_to_none = update_counters(
                        entry1["throughputMin"], entry2["throughputMin"], c_changes, c_from_none, c_to_none
                    )
                if not equal_tolerance(entry1["throughputMax"], entry2["throughputMax"]):
                    output += f"{entry1["llvmName"]} tpUpper {entry1["throughputMax"]} -> {entry2["throughputMax"]}\n"
                    c_changes, c_from_none, c_to_none = update_counters(
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
                    output += latString + "missing\n"
                    c_missing += 1
                else:
                    lat1_min = lat1["latencyMin"]
                    lat2_min = lat_map2[key]["latencyMin"]
                    lat1_max = lat1["latencyMax"]
                    lat2_max = lat_map2[key]["latencyMax"]
                    if lat1_min != lat2_min:
                        output += f"{latString} cyclesMin: {lat1_min} -> {lat2_min}\n"
                        c_changes, c_from_none, c_to_none = update_counters(
                            lat1_min, lat2_min, c_changes, c_from_none, c_to_none
                        )
                    if lat1_max != lat2_max:
                        output += f"{latString} cyclesMax: {lat1_max} -> {lat2_max}\n"
                        c_changes, c_from_none, c_to_none = update_counters(
                            lat1_max, lat2_max, c_changes, c_from_none, c_to_none
                        )
    if len(output_path) != 0:
        with open(output_path, "w") as f:
            f.write(output)
            print(f"wrote report to {output_path}")
    print(f"{c_changes} entries changed")
    print(f"{c_from_none} were None but have a value now")
    print(f"{c_to_none} had a value before but are None now")
    print(f"{c_missing} entries missing in new data")
