import os
import json
import common_functions as cf


# extract useful information from a tblgen dump
def build_quick_reference_files(input_file, output_dir):
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    data = {
        key: value for key, value in data.items() if key != "!instanceof" and isinstance(value, dict)
    }  # remove large first key
    processors = {key: value for key, value in data.items() if "Processor" in value["!superclasses"]}
    instructions = {key: value for key, value in data.items() if "Instruction" in value["!superclasses"]}
    features = {key: value for key, value in data.items() if "SubtargetFeature" in value["!superclasses"]}
    predicates = {key: value for key, value in data.items() if "Predicate" in value["!superclasses"]}
    DAGOperands = {key: value for key, value in data.items() if "DAGOperand" in value["!superclasses"]}
    registerClass = {key: value for key, value in data.items() if "RegisterClass" in value["!superclasses"]}
    registers = {key: value for key, value in data.items() if "Register" in value["!superclasses"]}
    # instr_superclasses = sorted(
    #     list(set([cl for cll in [isntr["!superclasses"] for isntr in instructions.values()] for cl in cll]))
    # )
    cf.dict_to_file(instructions, output_dir + "Instruction", True)
    cf.dict_to_file(processors, output_dir + "Processor", True)
    cf.dict_to_file(features, output_dir + "Feature", True)
    cf.dict_to_file(predicates, output_dir + "Predicate", True)
    cf.dict_to_file(DAGOperands, output_dir + "DAGOperand", True)
    cf.dict_to_file(registerClass, output_dir + "RegisterClass", True)
    cf.dict_to_file(registers, output_dir + "Register", True)
    # cf.dict_to_file({"superclasses": instr_superclasses}, "superclass")


os.makedirs("analysis/reference-files/X86", exist_ok=True)
os.makedirs("analysis/reference-files/AArch64", exist_ok=True)
os.makedirs("analysis/reference-files/RISCV", exist_ok=True)
build_quick_reference_files("analysis/reference-files/X86.json", "analysis/reference-files/X86/")
build_quick_reference_files("analysis/reference-files/AArch64.json", "analysis/reference-files/AArch64/")
build_quick_reference_files("analysis/reference-files/RISCV.json", "analysis/reference-files/RISCV/")
