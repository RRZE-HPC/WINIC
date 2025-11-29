from analysis.globals import *
from analysis.parsing.parse_llvm import parse_LLVM_instruction
from pprint import pprint


def parse_WINIC_instruction(dbEntry) -> Instruction:
    instruction = parse_LLVM_instruction(dbEntry["llvmName"])
    if instruction is None:
        return None
    # instruction.throughputs[0].cyclesMin = dbEntry.get("throughputMin", None)
    # instruction.throughputs[0].cyclesMax = dbEntry.get("throughputMax", None)
    instruction.throughputs.append(Throughput(dbEntry.get("throughputMin", None), dbEntry.get("throughputMax", None)))
    operand_latencies = dbEntry.get("operandLatencies", {})
    for lat in operand_latencies:
        sourceOp: str = lat["sourceOperand"]
        # if "ADC16ri" in dbEntry["llvmName"]:
        #     print(lat)
        #     print(lat["sourceOperand"])
        #     exit(1)
        targetOp = lat["targetOperand"]
        if sourceOp.isnumeric():
            sourceIndex = int(sourceOp) + 1  # uops counts from 1, winic from 0
        else:
            # need to find index generated for that operand by parse_LLVM_instruction
            sourceIndex = next(
                (op.index for op in instruction.operands if len(op.regList) == 1 and op.regList[0] == sourceOp), None
            )
        if targetOp.isnumeric():
            targetIndex = int(targetOp) + 1  # uops counts from 1, winic from 0
        else:
            # need to find index generated for that operand by parse_LLVM_instruction
            targetIndex = next(
                (op.index for op in instruction.operands if len(op.regList) == 1 and op.regList[0] == targetOp), None
            )
        if "latencyMin" in lat and "latencyMax" in lat:
            instruction.latencies.append(Latency(sourceIndex, targetIndex, lat["latencyMin"], lat["latencyMax"]))
        else:
            pprint(lat)  # database malformed
            pprint(instruction, compact=True)
            pprint(dbEntry, compact=True)
            exit(1)
    return instruction
