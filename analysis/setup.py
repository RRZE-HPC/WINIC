import os
import json
import subprocess
import urllib.request
from .globals import dict_to_file


def gen_tblgen_dumps(llvm_dir, llvm_project_dir, force=False):
    print("generating tblgen dumps for all architectures")
    for arch in ["X86", "AArch64", "RISCV"]:
        out_path = f"analysis/reference-files/{arch}.json"
        if os.path.exists(out_path) and not force:
            print(f"\t{out_path} already exists, skipping (use --force to overwrite)")
            continue
        command = [
            llvm_dir + "/bin/llvm-tblgen",
            "-I",
            llvm_project_dir + "/llvm/include",
            "-I",
            f"{llvm_project_dir}/llvm/lib/Target/{arch}",
            f"{llvm_project_dir}/llvm/lib/Target/{arch}/{arch}.td",
            "-dump-json",
        ]
        with open(out_path, "w") as f:
            print(f"\trunnning {' '.join(command)}")
            result = subprocess.run(command, stdout=f)
            if result.stderr is not None:
                print("stderr: " + result.stderr)  # standard error


# extract useful information from a tblgen dump
def gen_quick_reference_files(input_file, output_dir, force=False):
    if not os.path.exists(input_file):
        print(f'{input_file} was not found, did you already run "setup --type dump" before calling this?')
        return
    with open(input_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except FileNotFoundError:
            print(f'{input_file} was not found, did you already run "setup --type dump" before calling this?')
    print(f"extracting useful information out of {input_file} into separate files")
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
    for name, obj in [
        ("Instruction", instructions),
        ("Processor", processors),
        ("Feature", features),
        ("Predicate", predicates),
        ("DAGOperand", DAGOperands),
        ("RegisterClass", registerClass),
        ("Register", registers),
    ]:
        out_path = output_dir + name
        if os.path.exists(out_path) and not force:
            print(f"\t{out_path} already exists, skipping (use --force to overwrite)")
            continue
        dict_to_file(obj, out_path, True)
    # cf.dict_to_file({"superclasses": instr_superclasses}, "superclass")


def download_uops_database(force=False):
    url = "https://uops.info/instructions.xml"
    out_path = "analysis/reference-files/uops.xml"
    if os.path.exists(out_path) and not force:
        print("uops.info database already exists, use --force to download it anyways")
        return
    print("downloading uops.info database from https://uops.info/instructions.xml")
    urllib.request.urlretrieve(url, out_path)
