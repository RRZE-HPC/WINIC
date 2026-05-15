import copy
import itertools
from analysis.globals import *
from dataclasses import dataclass


def _short_op(op: Operand) -> str:
    return f"({op.type} {op.width} {op.metadata})"


# returns a similarity score for two operands.
# the final metric is obtained by looking at operand width and metadata
# if width = -1 this produces a weaker match metric
# if metadata is * this produces a weaker match metric
# score | type | width  | metadata
# 0     | no   | any    | any
# 0     | any  | no     | any
# 0     | any  | any    | no
# 1     | yes  | weak   | weak
# 2     | yes  | strong | missing
# 3     | yes  | strong | missing + weak
# 4     | yes  | weak   | weak
# 5     | yes  | strong | weak
# 5     | yes  | weak   | strong
# 6     | yes  | strong | strong
# WARNING: O(n!) algorithm, don't use with large operand lists
def operand_similarity(operands1: List[Operand], operands2: List[Operand], debug=False):
    # remove implicit operands as they are not listed in the amd document
    operands1 = [o for o in operands1 if o.suppressed == False]
    operands2 = [o for o in operands2 if o.suppressed == False]
    if len(operands1) != len(operands2):
        if debug:
            print(f"different length: {operands1}, {operands2}")
        return 0  # not even the same number of operands
    # if debug:
    #     print(f"comparing {operands1} to {operands2}")

    # This is a very inefficient algorithm as im too stupid to write something faster but since operand lists are normally not longer than 3 its fine
    perm = itertools.permutations(operands1)
    match_strength = 0
    if debug:
        print(f"order of op2: {operands2}")

    for p in list(perm):
        p_strength = 6
        if debug:
            print(f"---permutation: {[_short_op(op) for op in p]}")
        # calculate match metric of permutation of op1 with op2
        for o1, o2 in zip(p, operands2):
            if debug:
                print(f"comparing {_short_op(o1)}, {_short_op(o2)}")
            o_strength = 6
            if o1.type != o2.type:
                p_strength = 0  # type mismatch, invalidate permutation
                if debug:
                    print(f"type mismatch")
                break
            if o1.width != o2.width:
                if -1 not in [o1.width, o2.width]:
                    # no width match, invalidate permutation
                    p_strength = 0
                    if debug:
                        print(f"\twidth mismatch {o1.width} != {o2.width}, exit")
                    break
                # weak width match, reduces max strength by 1
                o_strength -= 1
                if debug:
                    print(f"\twidth weak match {o1.width} != {o2.width}, subtract 1")
            else:
                if debug:
                    print("\twidth match")
            if debug:
                print(f"operand score after width check: {o_strength}")
            # check metadata
            weak_metadata = False
            missing_metadata = False
            for m in o1.metadata.keys() | o2.metadata.keys():
                if m not in o1.metadata.keys() or m not in o2.metadata.keys():
                    # metadata missing -> strong penalty bu not invalidating match
                    missing_metadata = True
                    if debug:
                        print(f"\tmissing metadata: {m}, i will remember this!")
                    continue
                val1 = o1.metadata[m]
                val2 = o2.metadata[m]
                if val1 != val2:
                    weak_metadata = True
                    if "*" not in [val1, val2]:
                        # direct metadata mismatch -> invalidate permutation
                        if debug:
                            print(f"\tmetadata mismatch: {val1} != {val2}, failing")
                        p_strength = 0
                        break
                    if debug:
                        print(f"\t{val1=} != {val2=} , set {weak_metadata=}")
            else:  # for ... else block is executed if the for loop finished *without* early exit
                if debug:
                    print(f"score before metadata: {o_strength}")
                o_strength -= 1 if weak_metadata else 0
                o_strength -= 3 if missing_metadata else 0
                if debug:
                    print(f"score after metadata: {o_strength}")
                # permutation gets assigned the worst operand strength
                p_strength = min(p_strength, o_strength)
                continue
            break  # only reached if metadata loop was exited early -> permutation invalid

        # get the maximum over all permutations
        match_strength = max(p_strength, match_strength)
        if debug:
            print(f"\t total: {p_strength=} new {match_strength=}\n")
    return match_strength


@dataclass
class CompareCounters:
    c_lat_full: int = 0  # for how many instuctions do all latency values match with the other source
    c_lat_partial: int = 0  # for how many instuctions do some latency values match with the other source
    c_lat_no: int = 0  # for how many instuctions does none of the latency values match with the other source
    c_tp_full: int = 0
    c_tp_partial: int = 0
    c_tp_no: int = 0


# def get_stats(
#     w_inst: Instruction,
#     o_inst: Instruction,
#     counters: CompareCounters,
#     mode: Literal["TP", "LAT", "BOTH"] = "BOTH",
#     pr: bool = False,
# ):
#     assert mode in ["TP", "LAT", "BOTH"]
#     found_tp_match = False
#     found_lat_match = False
#     found_lat_no_match = False
#     found_tp_no_match = False

#     if mode in ["LAT", "BOTH"]:
#         for lat in w_inst.latencies:
#             if lat.cyclesMin is None:
#                 continue

#             if lat_possible_in(lat, o_inst):
#                 found_lat_match = True
#             else:
#                 found_lat_no_match = True
#                 if pr:
#                     print(f"{'{'}inst: {w_inst}, impossible_value: {lat}, compared_to: {o_inst}{'}'}")
#     # throughputs
#     if mode in ["TP", "BOTH"]:
#         for tp in w_inst.throughputs:
#             if tp.cyclesMin is None:
#                 continue
#             if tp_possible_in(tp, o_inst):
#                 found_tp_match = True
#             else:
#                 found_tp_no_match = True
#                 if pr:
#                     print(f"{'{'}inst: {w_inst}, impossible_value: {tp}, compared_to: {o_inst}{'}'}")

#     if found_lat_match:
#         if found_lat_no_match:
#             counters.c_lat_partial += 1
#         else:
#             counters.c_lat_full += 1
#     else:
#         counters.c_lat_no += 1

#     if found_tp_match:
#         if found_tp_no_match:
#             counters.c_tp_partial += 1
#         else:
#             counters.c_tp_full += 1
#     else:
#         counters.c_tp_no += 1

#     return counters


def get_stats(
    w_inst: Instruction,
    o_inst: Instruction,
    counters: CompareCounters,
    mode: Literal["TP", "LAT", "BOTH"] = "BOTH",
    verbose: bool = False,
):
    assert mode in ["TP", "LAT", "BOTH"]

    if mode in ["LAT", "BOTH"]:
        if has_lat(w_inst):
            cl = classify_match(w_inst, o_inst, "LAT")
            if cl == "FULL":
                counters.c_lat_full += 1
            elif cl == "PARTIAL":
                if verbose:
                    print(f"{'{'}partial_lat_match: {w_inst}, other: {o_inst}{'}'}")
                counters.c_lat_partial += 1
            else:
                if verbose:
                    print(f"{'{'}no_lat_match_at_all: {w_inst}, other: {o_inst}{'}'}")
                counters.c_lat_no += 1

    if mode in ["TP", "BOTH"]:
        if has_tp(w_inst):
            cl = classify_match(w_inst, o_inst, "TP")
            if cl == "FULL":
                counters.c_tp_full += 1
            elif cl == "PARTIAL":
                if verbose:
                    print(f"{'{'}partial_tp_match: {w_inst}, other: {o_inst}{'}'}")
                counters.c_tp_partial += 1
            else:
                if verbose:
                    print(f"{'{'}no_tp_match_at_all: {w_inst}, other: {o_inst}{'}'}")
                counters.c_tp_no += 1

    return counters


def _short(inst: Instruction) -> str:
    ops = ""
    for op in inst.operands:
        ops += f"({op.type}, {op.width}"
        if op.metadata:
            ops += f",{op.metadata}"
        if op.suppressed:
            ops += f", supp=1"
        ops += "),"

    tps = ", ".join([f"TP({tp.cyclesMin}-{tp.cyclesMax})" for tp in inst.throughputs])
    lats = ", ".join([f"LAT({lat.cyclesMin}-{lat.cyclesMax})" for lat in inst.latencies])
    string = "Inst("
    if inst.source != "":
        string += inst.source + ", "
    if inst.sourceName != "":
        string += inst.sourceName + ", "
    if inst.asmName != "":
        string += inst.asmName + ", "
    string += ops + ", "
    if len(inst.throughputs) != 0:
        string += tps + ", "
    if len(inst.latencies) != 0:
        string += lats + ", "
    if len(inst.metadata) != 0:
        string += str(inst.metadata)
    string += ")"
    return string


def _normalize_name(inst_name: str):
    # make lowercase, remove e.g. .16b
    return inst_name.upper().split(".")[0]


# assumes o_instructions have the correct mnemonic
# in conservative mode, if there are multiple matching instructions, the instruction will be treated as if it had no match
# in loose mode, multiple matches are combined into one and then classified according to the usual rules
def compare_lists(
    w_instructions: List[Instruction],
    o_instructions: List[Instruction],
    mode: Literal["TP", "LAT", "BOTH"] = "BOTH",
    strictness: Literal["conservative", "loose"] = "conservative",
    verbose: bool = False,
) -> CompareCounters:
    # o_match_map: dict[str, list[str]] = {}
    # def track_match(w_inst: Instruction, o_inst: Instruction):
    #     w_str = _short(w_inst)
    #     o_str = _short(o_inst)
    #     if o_str in o_match_map.keys():
    #         o_match_map[o_str].append(w_str)
    #     else:
    #         o_match_map[o_str] = [w_str]
    o_inst_map: dict[str, List[Instruction]] = {}
    for o_inst in o_instructions:
        map_name = _normalize_name(o_inst.asmName)
        if map_name in o_inst_map.keys():
            o_inst_map[map_name].append(o_inst)
        else:
            o_inst_map[map_name] = [o_inst]
    # match stats
    c_no_match = 0
    c_multiple_matches = 0
    c_one_match = 0
    counters: CompareCounters = CompareCounters()
    debug = False
    for w_inst in w_instructions:
        foundCandidates = False
        name = _normalize_name(w_inst.asmName)
        if name not in o_inst_map.keys():
            continue

        o_candidates: List[Instruction] = o_inst_map[name]
        foundCandidates = True
        if w_inst.sourceName == "abc":
            debug = True
            print("handling")
            print(_short(w_inst))
            print("candidates:")
            print([c for c in o_candidates])
        # o_candidates = [c for c in o_candidates if same_metadata(w_inst, c)]
        scored_candidates = [[], [], [], [], [], [], []]  # candidates scored by value 1-5 higher is better
        for c in o_candidates:
            sim_score = operand_similarity(w_inst.operands, c.operands, debug)
            if sim_score != 0:
                scored_candidates[sim_score].append(c)
        if debug:
            print(f"{scored_candidates=}")
            exit(0)
        debug = False
        if sum(len(s) for s in scored_candidates) == 0:
            c_no_match += 1
            # if foundCandidates:
            #     print("no matches:")
            #     print(_short(w_inst))
            #     pprint(f"candidates_by_name: {[_short(c) for c in o_candidates]}")
            #     print("\n")
            continue

        highest_score_bin: List[Instruction] = []
        for s in scored_candidates:
            if len(s) != 0:
                highest_score_bin = s
        if len(highest_score_bin) == 0:
            c_one_match += 1
        elif len(highest_score_bin) > 1:
            c_multiple_matches += 1
            # there are multiple candidates with operands matching.
            # print("multiple matches:")
            # print(_short(w_inst))
            # for s in scored_candidates:
            #     print(f"scored_candidates: {[_short(c) for c in s]}")
            # print("\n")
            if strictness == "conservative":
                continue
            # loose mode: create one instruction containing all unique values of all matches
            n_inst = copy.deepcopy(highest_score_bin[0])
            n_inst.throughputs.clear()
            n_inst.latencies.clear()
            lat_seen = []
            tp_seen = []
            for c in highest_score_bin:
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
            highest_score_bin = [n_inst]

        # bin with highest score has only one element, this is our match
        o_inst = highest_score_bin[0]
        # track_match(w_inst, o_inst)
        # if o_inst in o_unmatched:
        #     o_unmatched.remove(o_inst)
        # if w_inst in w_unmatched:
        #     w_unmatched.remove(w_inst)

        counters = get_stats(w_inst, o_inst, counters, mode, verbose)

    # check total number of instruction with value
    c_lat_obtained = 0  # how many instructions have a latency value
    c_tp_obtained = 0
    for w_inst in w_instructions:
        if any([l for l in w_inst.latencies if l.cyclesMin != None]):
            c_lat_obtained += 1
        if any([tp for tp in w_inst.throughputs if tp.cyclesMin != None]):
            c_tp_obtained += 1
    print("instruction stats:")
    print(f"{c_lat_obtained=}")
    print(f"{c_tp_obtained=}\n")
    print(f"{c_one_match=}")
    print(f"{c_multiple_matches=}")
    print(f"{c_no_match=}")

    # print results
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
    return counters


def count_instrs_with_values(w_instructions: List[Instruction]):
    # check total number of instruction with value
    c_lat_obtained = 0  # how many instructions have a latency value
    c_tp_obtained = 0
    for w_inst in w_instructions:
        if any(l.cyclesMin != None for l in w_inst.latencies):
            c_lat_obtained += 1
        if any(tp.cyclesMin != None for tp in w_inst.throughputs):
            c_tp_obtained += 1
    return (c_tp_obtained, c_lat_obtained)


# full match: each value in o_inst is also in w_inst or: o_inst has a range and w_inst has values at both ends of the range
# partial match: at least one value in o_inst is also in w_inst or: o_inst has a range and w_inst has a value within that range
# no match: no values in o_inst are also in w_inst
def classify_match(w_inst: Instruction, o_inst: Instruction, mode: Literal["TP", "LAT"]):
    def is_range(val):
        return val.cyclesMin != val.cyclesMax

    # set tolerance here
    tolerance = 0.1

    def eq(v1: float, v2: float):
        v_tolerance = max(v1, v2) * tolerance
        return abs(v1 - v2) < v_tolerance

    def geq(v1: float, v2: float):
        return v1 > v2 or eq(v1, v2)

    def leq(v1: float, v2: float):
        return v1 < v2 or eq(v1, v2)

    def values_overlap(val1, val2):
        return not leq(val1.cyclesMax, val2.cyclesMin) or geq(val1.cyclesMin, val2.cyclesMax)
        # return not val1.cyclesMax < val2.cyclesMin * (1 - tolerance) or val1.cyclesMin > val2.cyclesMax * (
        #     1 + tolerance
        # )

    if mode == "LAT":
        values_to_check_w = w_inst.latencies
        values_to_check_o = o_inst.latencies
    else:
        values_to_check_w = w_inst.throughputs
        values_to_check_o = o_inst.throughputs
    # assure there are no None values anywhere
    values_to_check_w = [v for v in values_to_check_w if v.cyclesMax is not None and v.cyclesMin is not None]
    values_to_check_o = [v for v in values_to_check_o if v.cyclesMax is not None and v.cyclesMin is not None]

    found_matching_val = False
    found_non_matching_val = False
    # check special case o has range and WINIC covers start and end point
    # normally a range will count as partial match but if WINIC covers each end of the range we consider this as full match
    # this makes sense as WINIC measures single values and documentation might provide ranges
    to_replace = []
    for o_value in values_to_check_o:
        if not is_range(o_value):
            continue
        max_covered = False
        min_covered = False
        for w_value in values_to_check_w:
            # check max is covered and winic range does not exceed other range
            if eq(w_value.cyclesMax, o_value.cyclesMax) and geq(w_value.cyclesMin, o_value.cyclesMin):
                max_covered = True
            if eq(w_value.cyclesMin, o_value.cyclesMin) and geq(o_value.cyclesMax, w_value.cyclesMax):
                min_covered = True
        if not min_covered and max_covered:
            # check if this range has any matches
            for w_value in values_to_check_w:
                if values_overlap(w_value, o_value):
                    found_matching_val = True
                    break
            else:  # executed if loop did not break
                found_non_matching_val = True
        # this range should not cause a partial match so we replace it with its start and end point
        to_replace.append(o_value)
        # for rem_val in range(o_value.cyclesMin, o_value.cyclesMax):
        # if equal_tolerance(rem_val, o_value.cyclesMin) or equal_tolerance(rem_val, o_value.cyclesMax):
        #     continue  # don't remove start and end points
        # values_o.remove(rem_val)
        # values_w.remove(rem_val)
    for v in to_replace:
        values_to_check_o.remove(v)
        # we just use TPs here as it doesn't matter in later code (which yes, is ugly)
        values_to_check_o.append(Throughput(v.cyclesMin, v.cyclesMin))
        values_to_check_o.append(Throughput(v.cyclesMax, v.cyclesMax))

    assert not any(is_range(v) for v in values_to_check_o)

    # now the other way round, but for WINIC, ranges are uncertainties - not facts, so they always cause partial matches
    temp = []
    for w_value in values_to_check_w:
        if not is_range(w_value):
            temp.append(w_value)
            continue
        for o_value in values_to_check_o:
            # if values_overlap(o_value, w_value):
            if geq(o_value.cyclesMax, w_value.cyclesMin) and leq(o_value.cyclesMax, w_value.cyclesMax):
                return "PARTIAL"
        found_non_matching_val = True
    values_to_check_w = temp

    assert not any(is_range(v) for v in values_to_check_w)

    # from now on there are no ranges left
    values_o = set([v.cyclesMin for v in values_to_check_o])
    values_w = set([v.cyclesMin for v in values_to_check_w])

    for o_value in values_o:
        if any(eq(w_value, o_value) for w_value in values_w):
            found_matching_val = True
        else:
            found_non_matching_val = True
    for w_value in values_w:
        if any(eq(w_value, o_value) for o_value in values_o):
            found_matching_val = True
        else:
            found_non_matching_val = True

    if found_matching_val and not found_non_matching_val:
        return "FULL"
    elif found_matching_val:
        return "PARTIAL"
    else:
        return "NO"


def equal_tolerance(val1: float, val2: float, tolerance: float):
    if val1 == val2:
        return True
    if val1 == None or val2 == None:
        return False
    return val1 * (1 - tolerance) < val2 < val1 * (1 + tolerance)


# if the latency is a range, check that there is at least one value or range in ref_inst that allows any value in that range. (with a tolerance of 10%)
# this is the weakest condition possible to classify a value as "correct" assuming the reg_inst represents the truth
# def lat_possible_in(lat: Latency, ref_inst: Instruction):
#     if any(x is None for x in [lat, lat.cyclesMin, lat.cyclesMax]):
#         return True
#     for ref_lat in ref_inst.latencies:
#         if any(x is None for x in [ref_lat, ref_lat.cyclesMin, ref_lat.cyclesMax]):
#             continue
#         if not lat.cyclesMax < ref_lat.cyclesMin * 0.9 or lat.cyclesMin > ref_lat.cyclesMax * 1.1:
#             return True
#     return False


# def tp_possible_in(tp: Throughput, ref_inst: Instruction):
#     if any(x is None for x in [tp, tp.cyclesMin, tp.cyclesMax]):
#         return True
#     for ref_tp in ref_inst.throughputs:
#         if any(x is None for x in [ref_tp, ref_tp.cyclesMin, ref_tp.cyclesMax]):
#             continue
#         if not tp.cyclesMax < ref_tp.cyclesMin * 0.9 or tp.cyclesMin > ref_tp.cyclesMax * 1.1:
#             return True
#     return False
