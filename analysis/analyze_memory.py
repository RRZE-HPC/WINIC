import json
import sys
import os

# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import common_functions as cf
from matplotlib import pyplot as plt
from matplotlib_venn import venn3, venn3_circles
from matplotlib_venn.layout.venn3 import DefaultLayoutAlgorithm


# compare different ways to find instructions which access memorys
def analyze_memory_identification_methods(arch_json):
    with open(arch_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    data = {
        key: value for key, value in data.items() if key != "!instanceof" and isinstance(value, dict)
    }  # remove large first key
    instructions = {key: value for key, value in data.items() if "Instruction" in value["!superclasses"]}

    i_flags = set([])
    for key, value in instructions.copy().items():
        if value["mayLoad"] == 1 or value["mayStore"] == 1:
            # i_flags[key] = value
            i_flags.add(key)

    i_superclasses = set([])
    for key, value in instructions.copy().items():
        s_classes = str(value["!superclasses"])
        if "Load" in s_classes or "Store" in s_classes or "mem" in s_classes:
            # i_superclasses[key] = value
            i_superclasses.add(key)

    i_brackets = set([])
    for key, value in instructions.copy().items():
        if "[" in value["AsmString"]:
            # i_brackets[key] = value
            i_brackets.add(key)

    # print(len(i_flags))
    # print(len(i_superclasses))
    # print(len(i_brackets))

    print(i_superclasses.intersection(i_flags).difference(i_brackets))
    v = venn3(
        [i_flags, i_superclasses, i_brackets],
        ("flags", "superclasses", "brackets"),
        layout_algorithm=DefaultLayoutAlgorithm(fixed_subset_sizes=(1, 1, 1, 1, 1, 1, 1)),
    )

    print(list(set(instructions.keys()).difference(i_flags).difference(i_brackets).difference(i_superclasses))[:10])
    plt.tight_layout()
    plt.savefig("analysis/memory.svg")


# analyze_memory_identification_methods("analysis/reference-files/X86.json")
analyze_memory_identification_methods("analysis/reference-files/AArch64.json")
# analyze_memory_identification_methods("analysis/reference-files/RISCV.json")
