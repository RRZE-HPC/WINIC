from dataclasses import dataclass, field
from typing import List, Literal
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

dbg = False


def debug(msg, level=0):
    global dbg
    for _ in range(level):
        msg = "  " + msg
    if dbg:
        print(msg)


@dataclass
class Counters:
    dbEntryC: int
    dbEmptyValueC: int
    internalErrorC: int
    noMatchC: int
    uniqueMatchSameValueC: int
    multiMatchSameValueC: int
    uniqueMatchDiffValueC: int
    multiMatchDiffValueC: int
    noUopsDataC: int


# --- unified datastructures --- #
@dataclass
class Operand:
    index: int = -1
    type: Literal["reg", "imm", "mem", "mask", "flags"] = "reg"
    width: int = -1
    read: bool = False
    write: bool = False
    suppressed: bool = False
    regList: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)  # a key: * means this datapoint can match any value of the key

    # note that the index is not relevant when comparing operands as it cannot be guaranteed
    # to be the same for an instruction parsed from uops and one parsed from LLVM
    def __eq__(self, value):
        if not isinstance(value, Operand):
            return NotImplemented
        return (
            self.type == value.type
            and self.read == value.read
            and self.write == value.write
            and self.width == value.width
            and self.suppressed == value.suppressed
            # reg lists dont have to match exactly, but make sure if one has exactly one register the other has one, too
            # as those are instructions as XOR AL, I8
            and not ((len(self.regList) != len(value.regList)) and (len(self.regList) == 1 or len(value.regList) == 1))
        )


@dataclass
class Latency:
    startOpIndex: int
    targetOpIndex: int
    cyclesMin: float
    cyclesMax: float

    def __post_init__(self):
        self.startOpIndex = int(self.startOpIndex) if self.startOpIndex is not None else None
        self.targetOpIndex = int(self.targetOpIndex) if self.targetOpIndex is not None else None
        self.cyclesMin = float(self.cyclesMin) if self.cyclesMin is not None else None
        self.cyclesMax = float(self.cyclesMax) if self.cyclesMax is not None else None


@dataclass
class Throughput:
    cyclesMin: float
    cyclesMax: float

    def __post_init__(self):
        self.cyclesMin = float(self.cyclesMin) if self.cyclesMin is not None else None
        self.cyclesMax = float(self.cyclesMax) if self.cyclesMax is not None else None

def val_eq(val1: Latency | Throughput, val2: Latency| Throughput, tolerance: float):
        v_tolerance = max(val1.cyclesMin, val2.cyclesMin) * tolerance
        if abs(val1.cyclesMin - val2.cyclesMin) > v_tolerance:
            return False
        
        v_tolerance = max(val1.cyclesMax, val2.cyclesMax) * tolerance
        if abs(val1.cyclesMax - val2.cyclesMax) > v_tolerance:
            return False
        

@dataclass
class Instruction:
    source: Literal["winic", "uops", "docs", "exegesis", "osaca"] = "winic"
    sourceName: str = ""
    asmName: str = ""
    operands: List[Operand] = field(default_factory=list)
    throughputs: List[Throughput] = field(default_factory=list)
    # throughput_lower: float = 0.0
    # throughput_upper: float = 0.0
    latencies: List[Latency] = field(default_factory=list)
    metadata: dict[str, bool] = field(default_factory=dict)  # additional info like AVX zeroing
    roundc: bool = False  # AVX512 roundc


# returns true if the metadata of the instructions does not conflict
def same_metadata(inst1: Instruction, inst2: Instruction):
    for k, v in inst1.metadata.items():
        if k in inst2.metadata.keys() and inst2.metadata[k] != v:
            return False
    return len(inst1.metadata) == len(inst2.metadata)

def has_lat(inst: Instruction) -> bool:
    return any(v.cyclesMin is not None for v in inst.latencies )

def has_tp(inst: Instruction) -> bool:
    return any(v.cyclesMin is not None for v in inst.throughputs)

# AI generated
def progress_bar(current, total, bar_length=40, prefix="Progress", suffix=""):
    """
    Displays a progress bar in the terminal that updates in place.
    Call this function repeatedly as progress advances.
    """
    percent = float(current) / total if total else 0
    filled_length = int(bar_length * percent)
    bar = "=" * filled_length + "-" * (bar_length - filled_length)
    print(f"\r{prefix}: |{bar}| {int(percent*100)}% {suffix}", end="", flush=True)
    if current >= total:
        print()  # Move to next line when done


# combine multiple databases, try to get as many non-null lat/tp values
def combine_dbs(dbs: List[List[Instruction]], mode: Literal["ReplaceNone", "FullMerge"]) -> List[Instruction]:
    def eq(v1: float, v2: float):
        v_tolerance = max(v1, v2) * 0.1
        return abs(v1 - v2) < v_tolerance
    print(f"combining {len(dbs)} databases")
    if len(dbs) == 1:
        return dbs[0]
    if mode == "ReplaceNone":
        combined: dict[str, Instruction] = {}
        contributions = [0 for _ in range(len(dbs))]
        count = 0
        for db in dbs:
            for inst in db:
                contributed = 0
                name = inst.sourceName
                if name not in combined:
                    contributed = 1
                    combined[name] = inst
                else:
                    # assume only one value
                    lat = combined[name].latencies
                    if any(v.cyclesMin is not None for v in inst.latencies):
                        if len(lat) == 0 or lat[0].cyclesMin is None:
                            print(f"Updating latencies for {name} from db {count}")
                            contributed = 1
                            combined[name].latencies = inst.latencies
                    tp = combined[name].throughputs
                    if any(v.cyclesMin is not None for v in inst.throughputs):
                        if len(tp) == 0 or tp[0].cyclesMin is None:
                            print(f"Updating throughputs for {name} from db {count}")
                            combined[name].throughputs = inst.throughputs
                            contributed = 1
                contributions[count] += contributed
            count += 1
        print(f"contributions per db: {contributions}")
        return combined.values()
    if mode == "FullMerge":
        combined: dict[str, Instruction] = {}
        for db in dbs:
            for inst in db:
                name = inst.sourceName
                if name not in combined:
                    contributed = 1
                    combined[name] = inst
                else:
                    for lat in inst.latencies:
                        if not any(val_eq(l, lat) for l in combined[name].latencies):
                            combined[name].latencies.append(lat)


# -----some json/yaml helper functions-----


# write a python dictionary to a file
def dict_to_file(dict: dict, name: str, repeat_name: bool = False):
    with open(name, "w") as f:
        for value in dict.values():
            if repeat_name:
                f.write(f'{value["!name"]}={str(value)}\n')
            else:
                f.write(f"{str(value)}\n")


# write a python dictionary to a json file
def dict_to_json(dict: dict, filename: str):
    import json

    with open(filename, "w") as f:
        json.dump(dict, f)


# write a python dictionary to a yaml file
def dict_to_yaml(dict: dict, filename: str):
    import yaml

    with open(filename, "w") as f:
        yaml.dump(dict, f)


# -----some unused llvm analysis-----


# features can imply other features
# this adds all implied features to the input list of features
def _expand_feature_set(features: list, all_features: dict):
    to_process = features.copy()  # feature string only
    expanded_features = features.copy()
    while len(to_process) > 0:
        feature_name = to_process.pop()

        feature = all_features[feature_name]
        for f in feature["Implies"]:
            implied_name = f["def"]
            if implied_name not in expanded_features:
                expanded_features.append(implied_name)
                to_process.append(implied_name)
    return expanded_features


# evaluates AArch64 and RISCV strings like (any_of FeatureAll, (any_of FeatureSSVE_FP8DOT2, (all_of FeatureSVE2, FeatureFP8DOT2)))
def _eval_predicate_string(pred_str: str, features):
    pred_str = pred_str.strip()
    # remove outermost brackets
    if pred_str[0] == "(":
        pred_str = pred_str[1:-1]
    if pred_str.startswith("any_of") or pred_str.startswith("all_of"):
        operation = pred_str[:6]
        pred_str = pred_str[6:]
        args = []
        stack = []
        current_arg = ""
        for c in pred_str:
            if c == "," and len(stack) == 0:
                args.append(current_arg)
                current_arg = ""
            else:
                if c == "(":
                    stack.append("(")
                if c == ")":
                    stack.pop()
                current_arg += c
        args.append(current_arg)

        if operation == "any_of":
            for arg in args:
                if _eval_predicate_string(arg, features):
                    return True
            return False
        if operation == "all_of":
            for arg in args:
                try:
                    if not _eval_predicate_string(arg, features):
                        return False
                except Exception:
                    print(pred_str)
            return True
    elif pred_str.startswith("not"):
        pred_str = pred_str.removeprefix("not")
        return not _eval_predicate_string(pred_str, features)
    else:
        return pred_str in features


# compare different ways to find pseudo instructions
def _analyze_pseudo_identification_methods(instructions: dict):
    from matplotlib_venn import venn3
    from matplotlib import pyplot as plt
    from matplotlib_venn.layout.venn3 import DefaultLayoutAlgorithm

    i_flags = set([])
    for key, value in instructions.copy().items():
        if value["isPseudo"] == 1:
            # i_flags[key] = value
            i_flags.add(key)

    i_superclasses = set([])
    for key, value in instructions.copy().items():
        s_classes = str(value["!superclasses"])
        if "Pseudo" in s_classes:
            # i_superclasses[key] = value
            i_superclasses.add(key)

    i_empty_asm_string = set([])
    for key, value in instructions.copy().items():
        if len(value["AsmString"]) == 0:
            # i_superclasses[key] = value
            i_empty_asm_string.add(key)

    # print(i_superclasses.intersection(i_flags).difference(i_brackets))
    v = venn3(
        [i_flags, i_superclasses, i_empty_asm_string],
        ("isPseudo flag", "Pseudo in superclasses", "empty asm string"),
        layout_algorithm=DefaultLayoutAlgorithm(fixed_subset_sizes=(1, 1, 1, 1, 1, 1, 1)),
    )

    # print(list(i_superclasses.difference(i_flags))[:10])
    # print(list(i_flags.difference(i_empty_asm_string))[:10])
    plt.title("Methods to detect pseudo instructions")
    plt.tight_layout()
    plt.show()
