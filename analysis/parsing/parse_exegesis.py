from analysis.globals import *
from typing import List
import yaml


def parse_exegesis(input_path: str) -> List[Instruction]:
    with open(input_path, "r") as file:
        raw_content = file.read().replace("\t", "    ")  # Replace tabs with 4 spaces

    inputs = [yaml.safe_load(m) for m in raw_content.split("---")[1:]]
    instruction_map: dict[str, Instruction] = {}
    

    for ex_result in inputs:
        # exegesis does measurements with interleaved loads, ignore those
        if len(ex_result["key"]["instructions"]) != 1:
            continue
        # ignore failed benchmarks
        if len(ex_result["measurements"]) == 0:
            continue
        llvm_name = ex_result["key"]["instructions"][0].split(" ")[0]
        value = ex_result["measurements"][0]["value"]
        mode = ex_result["mode"]
        if llvm_name not in instruction_map:
            instruction_map[llvm_name] = Instruction("exegesis", llvm_name, None, [], [], [])

        if mode == "latency":
            instruction_map.get(llvm_name).latencies.append(Latency(None, None, value, value))
        else:
            instruction_map.get(llvm_name).throughputs.append[Throughput(value, value)]
    return instruction_map.values()


if __name__ == "__main__":
    parse_exegesis("ISC/exegesis_spacemit.yaml")
