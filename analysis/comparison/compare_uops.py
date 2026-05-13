import copy
from analysis.globals import *
from analysis.parsing.parse_winic import read_WINIC_db
from typing import List, Literal
from pprint import pprint
import os


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
    if dbgInstruction != "" and dbgUopsInstructionString not in uopsInst.sourceName:
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
def compare_each_value(database, type: Literal["lat", "tp"], arch: str) -> Counters:
    # parse measured instructions
    from analysis.parsing.parse_winic import parse_WINIC_instruction
    from analysis.parsing.parse_uops import parse_uops_database

    db = read_WINIC_db(database)
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
            m_instr = parse_WINIC_instruction(db_entry, "X86")
            if m_instr is None:
                c.internalErrorC += 1
                continue
            llvm_name = db_entry["llvmName"]

            m_cycles = m_instr.throughputs[0].cyclesMin
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
                    0.92 * m_instr.throughputs[0].cyclesMin
                    <= u_instr.throughputs[0].cyclesMin
                    <= 1.09 * m_instr.throughputs[0].cyclesMax
                    for u_instr in u_matches
                ]
                debug([(u_inst.throughputs[0].cyclesMin, m_cycles) for u_inst in u_matches])
                debug(data_match)

                if False in data_match:
                    outputLines.append(
                        f"{llvm_name}: {u_matches[0].sourceName} uops: {u_matches[0].throughputs[0].cyclesMin}, WINIC: {m_cycles}, classify: differentVal(s)\n"
                    )
                    if len(data_match) == 1:
                        c.uniqueMatchDiffValueC += 1
                    else:
                        c.multiMatchDiffValueC += 1

                else:
                    outputLines.append(
                        f"{llvm_name}: {u_matches[0].sourceName} uops: {u_matches[0].throughputs[0].cyclesMin}, WINIC: {m_cycles}, classify: matchingVal(s)\n"
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

            # if u_instr.sourceName != "VDIVPD (XMM, K, XMM, XMM)":
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
                    # accept if WINIC range is in uops range
                    if m_lat.cyclesMin <= u_lat.cyclesMin and m_lat.cyclesMax >= u_lat.cyclesMax:
                        data_match.append(True)
                        outputLines.append(
                            f"{llvm_name}: {u_instr.sourceName} {u_lat.startOpIndex} -> {u_lat.targetOpIndex} uops: {u_lat.cyclesMin}-{u_lat.cyclesMax}, WINIC: {m_lat.cyclesMin}-{m_lat.cyclesMax}, classify: sameVal\n"
                        )
                    else:
                        data_match.append(False)
                        outputLines.append(
                            f"{llvm_name}: {u_instr.sourceName} {u_lat.startOpIndex} -> {u_lat.targetOpIndex} uops: {u_lat.cyclesMin}-{u_lat.cyclesMax}, WINIC: {m_lat.cyclesMin}-{m_lat.cyclesMax}, classify: differentVal\n"
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


def compare(database, mode: Literal["LAT", "TP", "BOTH"], march: str) -> Counters:
    from analysis.comparison.helper import CompareCounters, get_stats, count_instrs_with_values, compare_lists

    # parse measured instructions
    from analysis.parsing.parse_winic import parse_WINIC_instruction
    from analysis.parsing.parse_uops import parse_uops_database

    db = read_WINIC_db(database)
    uops_instructions = parse_uops_database(march)
    print(f"{len(uops_instructions)=}")
    w_instructions = [parse_WINIC_instruction(db_entry, "X86") for db_entry in db]
    print(w_instructions[:10])
    # compare_lists(w_instructions, uops_instructions, mode, "loose")
    counters = CompareCounters()
    c_no_match = 0
    c_multiple_matches = 0
    c_one_match = 0

    progress = 0
    outputLines = []
    w_instructions = []
    for db_entry in db:
        # progress += 1
        # progress_bar(progress, len(db))
        # if c.dbProgressC % 1000 == 0:
        #     print(c.dbProgressC)
        llvm_name = db_entry["llvmName"]
        if dbgInstruction != "" and llvm_name != dbgInstruction:
            continue

        w_instr = parse_WINIC_instruction(db_entry, "X86")
        if w_instr is None:
            continue
        w_instructions.append(w_instr)

        # find uops instsruction
        u_matches: List[Instruction] = []
        for u_instr in uops_instructions:
            if is_same(u_instr, w_instr):
                u_matches.append(u_instr)

        if len(u_matches) == 0:
            # outputLines.append(f"no_match: {llvm_name}\n")
            c_no_match += 1
            continue
        elif len(u_matches) > 1:
            # outputLines.append(f"multiple_matches: {llvm_name}\n")
            c_multiple_matches += 1
            # loose mode: create one instruction containing all unique values of all matches
            n_inst = copy.deepcopy(u_matches[0])
            n_inst.throughputs.clear()
            n_inst.latencies.clear()
            lat_seen = []
            tp_seen = []
            for c in u_matches:
                for lat in c.latencies:
                    l_tuple = (lat.cyclesMin, lat.cyclesMax)
                    if l_tuple not in lat_seen:
                        lat_seen.append(l_tuple)
                        n_inst.latencies.append(lat)
                for tp in c.throughputs:
                    l_tuple = (tp.cyclesMin, tp.cyclesMax)
                    if l_tuple not in tp_seen:
                        tp_seen.append(l_tuple)
                        n_inst.throughputs.append(tp)
            u_matches = [n_inst]
            # continue
        c_one_match += 1
        u_instr = u_matches[0]

        counters = get_stats(w_instr, u_instr, counters, "BOTH", True)

    for line in outputLines:
        print(line)

    print("match stats:")
    print(f"\t{c_no_match=}")
    print(f"\t{c_multiple_matches=}")
    print(f"\t{c_one_match=}")
    print("instruction stats:")
    c_tp_obtained, c_lat_obtained = count_instrs_with_values(w_instructions)
    print(f"{c_lat_obtained=}")
    print(f"{c_tp_obtained=}\n")
    c_total_lat = counters.c_lat_full + counters.c_lat_partial + counters.c_lat_no
    c_total_tp = counters.c_tp_full + counters.c_tp_partial + counters.c_tp_no
    if c_total_lat != 0:
        print(f"\t{counters.c_lat_full=}, {counters.c_lat_full*100/c_total_lat:.2f}%")
        print(f"\t{counters.c_lat_partial=}, {counters.c_lat_partial*100/c_total_lat:.2f}%")
        print(f"\t{counters.c_lat_no=}, {counters.c_lat_no*100/c_total_lat:.2f}%\n")
    if c_total_tp != 0:
        print(f"\t{counters.c_tp_full=}, {counters.c_tp_full*100/c_total_tp:.2f}%")
        print(f"\t{counters.c_tp_partial=}, {counters.c_tp_partial*100/c_total_tp:.2f}%")
        print(f"\t{counters.c_tp_no=}, {counters.c_tp_no*100/c_total_tp:.2f}%")
    return 0
