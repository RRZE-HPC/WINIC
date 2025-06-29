import json
import yaml
from matplotlib import pyplot as plt
from matplotlib_venn import venn3, venn3_circles
from matplotlib_venn.layout.venn3 import DefaultLayoutAlgorithm


def debug(level, msg):
    l = 1
    if level <= 2:
        print(msg)

#write a python dictionary to a file
def dict_to_file(dict: dict, name: str, repeat_name: bool = False):
    with open(name, "w") as f:
        for value in dict.values():
            if repeat_name:
                f.write(f'{value["!name"]}={str(value)}\n')
            else:
                f.write(f"{str(value)}\n")

#write a python dictionary to a json file
def dict_to_json(dict: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(dict, f)

#write a python dictionary to a yaml file
def dict_to_yaml(dict: dict, filename: str):
    with open(filename, "w") as f:
        yaml.dump(dict, f)


# features can imply other features
# this adds all implied features to the input list of features
def expand_feature_set(features: list, all_features: dict):
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


def convert_instruction(instruction):
    inst = {
        "NameLLVM": instruction["!name"],
        "AsmString": instruction["AsmString"],
        "InOperandList": [{"Type": arg[0]["def"], "Name": arg[1]} for arg in instruction["InOperandList"]["args"]],
        "OutOperandList": [{"Type": arg[0]["def"], "Name": arg[1]} for arg in instruction["OutOperandList"]["args"]],
        "Constraints": instruction["Constraints"],
    }
    return inst


# evaluates AArch64 and RISCV strings like (any_of FeatureAll, (any_of FeatureSSVE_FP8DOT2, (all_of FeatureSVE2, FeatureFP8DOT2)))
def eval_predicate_string(pred_str: str, features):
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
                if eval_predicate_string(arg, features):
                    return True
            return False
        if operation == "all_of":
            for arg in args:
                try:
                    if not eval_predicate_string(arg, features):
                        return False
                except Exception:
                    print(pred_str)
            return True
    elif pred_str.startswith("not"):
        pred_str = pred_str.removeprefix("not")
        return not eval_predicate_string(pred_str, features)
    else:
        return pred_str in features


# compare different ways to find pseudo instructions
def analyze_pseudo_identification_methods(instructions: dict):
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

