from typing import List, Literal
from analysis.globals import *
import os
import json
import re

_env = None


def _get_immidiate_width(imm: str):
    matches = re.findall(r"\d+", imm)
    return int(matches[-1]) if matches else None


class LLVMInterface:
    llvm_instructions = {}
    llvm_DAGOperands = {}

    # TODO implement support for aarch and RISCV
    def __init__(self, arch: Literal["X86", "AArch64"]):
        with open(os.path.join(script_dir, "reference-files", arch + ".json"), "r", encoding="utf-8") as f:
            data = json.load(f)

        data = {
            key: value for key, value in data.items() if key != "!instanceof" and isinstance(value, dict)
        }  # remove large first key
        self.llvm_instructions = {key: value for key, value in data.items() if "Instruction" in value["!superclasses"]}
        self.llvm_DAGOperands = {key: value for key, value in data.items() if "DAGOperand" in value["!superclasses"]}

    def get_instruction(self, llvm_name: str):
        if llvm_name not in self.llvm_instructions.keys():
            return None
        return self.llvm_instructions[llvm_name]

    def expand_regs(self, regs: list | str):
        result_regs = []
        if isinstance(regs, str):
            regs = [regs]
        for reg in regs:
            # weird llvm class
            if reg == "GR16orGR32orGR64":
                result_regs += self.expand_regs(["GR16"])
            if reg == "GR32orGR64":
                result_regs += self.expand_regs(["GR32"])
            if not reg in self.llvm_DAGOperands.keys():
                result_regs.append(reg)
                continue
            llvm_reg_class = self.llvm_DAGOperands[reg]
            if not "MemberList" in llvm_reg_class.keys():
                result_regs.append(reg)  # this not a register class
                continue
            if "%u" in str(llvm_reg_class["MemberList"]["args"]):
                # pattern for registers
                members = llvm_reg_class["MemberList"]["args"]
                base: str = members[0][0]
                # members has pattern and range of numbers to put in pattern
                try:
                    result_regs += [base.replace("%u", str(i)) for i in range(members[1][0], members[2][0])]
                except TypeError:
                    print("expand regs encountered malformed entry")
                    print(base)
                    return None
            else:
                # normal list of registers/registerclasses
                result_regs += self.expand_regs([arg[0]["def"] for arg in llvm_reg_class["MemberList"]["args"]])
        # debug(str(list(set(result_regs))[:5]) + "...")
        return list(set(result_regs))

    def identify_x86_LLVM_operand(self, opName):
        from analysis.parsing.helper import get_x86_register_width

        memoryMap = {
            "f32mem": ("mem", 32),
            "f64mem": ("mem", 64),
            "f128mem": ("mem", 128),
            "f256mem": ("mem", 256),
            "f512mem": ("mem", 512),
            "i8mem": ("mem", 8),
            "i16mem": ("mem", 16),
            "i32mem": ("mem", 32),
            "i64mem": ("mem", 64),
            "i128mem": ("mem", 128),
            "i256mem": ("mem", 256),
            "i512mem": ("mem", 512),
            "i8mem_NOREX": ("mem", 8),
            "sdmem": ("mem", -1),  # TODO
            "ssmem": ("mem", -1),
            "opaquemem": ("mem", -1),
        }

        if opName == "EFLAGS":
            return ("flags", None)
        if "mem" in opName:
            if opName not in memoryMap:
                print(f"missing mem op: {opName}")
                return ("mem", None)
            return memoryMap[opName]
        if opName in self.llvm_DAGOperands:
            operand = self.llvm_DAGOperands[opName]
            if "OperandType" in operand and operand["OperandType"] == "OPERAND_IMMEDIATE":
                return ("imm", _get_immidiate_width(opName))
            registers = self.expand_regs(opName)
        else:
            registers = [opName]

        return ("reg", get_x86_register_width(registers[0]))

    # unused, can decode complex LLVM operand names
    def get_aarch_operands(self, name: str, shapeHint: str = "") -> List[Operand]:
        # registers get width -1 if no value known and 0 if any value allowed (e.g. scalable)

        z_v_regs = {
            "V64": [Operand(-1, "reg", 64, metadata={"prefix": "v"})],
            "V128": [Operand(-1, "reg", 128, metadata={"prefix": "v"})],
            "V128_lo": [Operand(-1, "reg", 128, metadata={"prefix": "v"})],
            "ZPR8": [Operand(-1, "reg", 0, metadata={"shape": "b"})],
            "ZPR16": [Operand(-1, "reg", 0, metadata={"shape": "h"})],
            "ZPR32": [Operand(-1, "reg", 0, metadata={"shape": "s"})],
            "ZPR64": [Operand(-1, "reg", 0, metadata={"shape": "d"})],
            "ZZ_b": [Operand(-1, "reg", 0)],
            "ZZ_s": [Operand(-1, "reg", 0)],
            "ZZ_h": [Operand(-1, "reg", 0)],
            "ZZ_d": [Operand(-1, "reg", 0)],
            "Z_b": [Operand(-1, "reg", 0)],
            "Z_s": [Operand(-1, "reg", 0)],
            "Z_h": [Operand(-1, "reg", 0)],
            "Z_d": [Operand(-1, "reg", 0)],
            "ZPR3b16": [Operand(-1, "reg", 0)],
            "FPR8asZPR": [Operand(-1, "reg", 0)],  # logically FPR8 scalar but physically ZPR
            "FPR16asZPR": [Operand(-1, "reg", 0)],
            "FPR32asZPR": [Operand(-1, "reg", 0)],
            "FPR64asZPR": [Operand(-1, "reg", 0)],
            "ZPR64ExtUXTW8": [Operand(-1, "reg", 0)],
            "ZPR64ExtUXTW16": [Operand(-1, "reg", 0)],
            "ZPR64ExtUXTW32": [Operand(-1, "reg", 0)],
            "ZPR64ExtUXTW64": [Operand(-1, "reg", 0)],
            "ZPR64ExtSXTW8": [Operand(-1, "reg", 0)],
            "ZPR64ExtSXTW16": [Operand(-1, "reg", 0)],
            "ZPR64ExtSXTW32": [Operand(-1, "reg", 0)],
            "ZPR64ExtSXTW64": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL8": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL16": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL32": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL64": [Operand(-1, "reg", 0)],
            "ZPR64ExtLSL8": [Operand(-1, "reg", 0)],
            "ZPR64ExtLSL16": [Operand(-1, "reg", 0)],
            "ZPR64ExtLSL32": [Operand(-1, "reg", 0)],
            "ZPR64ExtLSL64": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL16": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL32": [Operand(-1, "reg", 0)],
            "ZPR32ExtLSL64": [Operand(-1, "reg", 0)],
        }
        if shapeHint != "":
            # all ZPR and V registers get a shape per default
            for regs in z_v_regs.values():
                for reg in regs:
                    reg.metadata["shape"] = shapeHint

        decode_map = {
            "GPR32": [Operand(-1, "reg", 32, metadata={"prefix": "w"})],
            "GPR32sp": [Operand(-1, "reg", 32, metadata={"prefix": "w"})],  # registers including SP
            "GPR32z": [Operand(-1, "reg", 32)],
            "GPR64": [Operand(-1, "reg", 64, metadata={"prefix": "x"})],
            "GPR64sp": [Operand(-1, "reg", 64, metadata={"prefix": "x"})],
            "GPR64z": [Operand(-1, "reg", 64)],  # forces XZR i think TODO check
            "ro_Xextend64": [Operand(-1, "reg", 64)],
            "ro_Wextend64": [Operand(-1, "reg", 64)],
            "X16": [Operand(-1, "reg", 64)],
            "X17": [Operand(-1, "reg", 64)],
            "LR": [Operand(-1, "reg", 64)],
            "PPRorPNR8": [Operand(-1, "reg", 8)],
            "PPRorPNRAny": [Operand(-1, "reg", 0)],
            "PPR8": [Operand(-1, "reg", 0)],
            "PPR16": [Operand(-1, "reg", 0)],
            "PPR32": [Operand(-1, "reg", 0)],
            "PPR64": [Operand(-1, "reg", 0)],
            "PPRAny": [Operand(-1, "reg", 0)],
            "FPR8": [Operand(-1, "reg", 8)],  # Those are part of v-registers
            "FPR16": [Operand(-1, "reg", 16, metadata={"prefix": "h"})],
            "FPR32": [Operand(-1, "reg", 32, metadata={"prefix": "s"})],
            "FPR64": [Operand(-1, "reg", 64, metadata={"prefix": "d"})],
            "FPR16Op": [Operand(-1, "reg", 16)],
            "FPR32Op": [Operand(-1, "reg", 32)],
            "FPR64Op": [Operand(-1, "reg", 64)],
            "FFR": [Operand(-1, "reg", -1)],  # TODO
            "VecListOne16b": [Operand(-1, "reg", 0)],
            "VecListTwo16b": [Operand(-1, "reg", 0), Operand(-1, "reg", 0)],
            "VecListThree16b": [Operand(-1, "reg", 0), Operand(-1, "reg", 0), Operand(-1, "reg", 0)],
            "VecListFour16b": [
                Operand(-1, "reg", 0),
                Operand(-1, "reg", 0),
                Operand(-1, "reg", 0),
                Operand(-1, "reg", 0),
            ],
            # special
            "NZCV": [Operand(-1, "reg", -1, suppressed=True)],  # FLAGS
            "FPCR": [Operand(-1, "reg", 64, suppressed=True)],
            "PPR3bAny": [Operand(-1, "reg", 0, metadata={"predicate": True})],
            # immediates
            "fpimm8": [Operand(-1, "imm", 8)],
            "fpimm16": [Operand(-1, "imm", 16)],
            "fpimm32": [Operand(-1, "imm", 32)],
            "fpimm64": [Operand(-1, "imm", 64)],
            "logical_imm32": [Operand(-1, "imm", 32)],
            "logical_imm64": [Operand(-1, "imm", 64)],
            "movimm16_shift": [Operand(-1, "imm", 16)],
            "movimm32_shift": [Operand(-1, "imm", 32)],
            "movimm64_shift": [Operand(-1, "imm", 64)],
            "i32imm": [Operand(-1, "imm", 32)],
            "movimm32_imm": [Operand(-1, "imm", 32)],
            "timm32_0_65535": [Operand(-1, "imm", 16)],
            "cpy_imm8_opt_lsl_i8": [Operand(-1, "imm", 8)],
            "cpy_imm8_opt_lsl_i16": [Operand(-1, "imm", 16)],
            "cpy_imm8_opt_lsl_i32": [Operand(-1, "imm", 32)],
            "cpy_imm8_opt_lsl_i64": [Operand(-1, "imm", 64)],
            "simdimmtype10": [Operand(-1, "imm", -1)],  # 10
            "addsub_imm8_opt_lsl_i8": [Operand(-1, "imm", 8)],
            # "sve_pred_enum": [Operand(-1, "imm", -1)],
            "imm32_0_15": [Operand(-1, "imm", -1)],  # 4 TODO unsure
            "imm32_0_31": [Operand(-1, "imm", -1)],  # 5
            "imm0_15": [Operand(-1, "imm", -1)],  # 4
            "imm0_31": [Operand(-1, "imm", -1)],  # 5
            "imm0_63": [Operand(-1, "imm", -1)],  # 6
            "imm0_127": [Operand(-1, "imm", -1)],  # 7
            "imm0_127_64b": [Operand(-1, "imm", -1)],  # 7
            "imm0_255": [Operand(-1, "imm", -1)],  # 8
            "timm32_0_7": [Operand(-1, "imm", -1)],
            "sve_fpimm_zero_one": [Operand(-1, "imm", -1)],  # 1
            "fixedpoint_f16_i32": [Operand(-1, "imm", -1)],
            "fixedpoint_f32_i32": [Operand(-1, "imm", -1)],
            "fixedpoint_f64_i32": [Operand(-1, "imm", -1)],
            "fixedpoint_f16_i64": [Operand(-1, "imm", -1)],
            "fixedpoint_f32_i64": [Operand(-1, "imm", -1)],
            "fixedpoint_f64_i64": [Operand(-1, "imm", -1)],
            "fixedpoint_recip_f16_i32": [Operand(-1, "imm", -1)],  # 6, ignore i32
            "fixedpoint_recip_f32_i32": [Operand(-1, "imm", -1)],  # 6
            "fixedpoint_recip_f64_i32": [Operand(-1, "imm", -1)],  # 6
            "fixedpoint_recip_f16_i64": [Operand(-1, "imm", -1)],  # 6
            "fixedpoint_recip_f32_i64": [Operand(-1, "imm", -1)],  # 6
            "fixedpoint_recip_f64_i64": [Operand(-1, "imm", -1)],  # 6
            "sve_fpimm_half_one": [Operand(-1, "imm", -1)],
            "sve_fpimm_half_two": [Operand(-1, "imm", -1)],
            "uimm6": [Operand(-1, "imm", -1)],  # 6
            "uimm6s16": [Operand(-1, "imm", -1)],  # technically width 6
            "uimm12s8": [Operand(-1, "imm", -1)],
            "simm5_8b": [Operand(-1, "imm", -1)],  #  5
            "simm5_16b": [Operand(-1, "imm", -1)],  #  5
            "simm5_32b": [Operand(-1, "imm", -1)],  #  5
            "simm5_64b": [Operand(-1, "imm", -1)],  #  5
            "simm6_32b": [Operand(-1, "imm", -1)],
            "simm8_32b": [Operand(-1, "imm", -1)],  #  8
            "simm9": [Operand(-1, "imm", -1)],  #  8
            "vecshiftL8": [Operand(-1, "imm", -1)],  #  3
            "vecshiftL16": [Operand(-1, "imm", -1)],  #  4
            "vecshiftL32": [Operand(-1, "imm", -1)],  #  5
            "vecshiftL64": [Operand(-1, "imm", -1)],  #  6
            "vecshiftR8": [Operand(-1, "imm", -1)],  #  3
            "vecshiftR16": [Operand(-1, "imm", -1)],  #  4
            "vecshiftR32": [Operand(-1, "imm", -1)],  #  5
            "vecshiftR64": [Operand(-1, "imm", -1)],  #  6
            "vecshiftR16Narrow": [Operand(-1, "imm", -1)],
            "vecshiftR32Narrow": [Operand(-1, "imm", -1)],
            "vecshiftR64Narrow": [Operand(-1, "imm", -1)],
            "tvecshiftR8": [Operand(-1, "imm", -1)],
            "tvecshiftR16": [Operand(-1, "imm", -1)],
            "tvecshiftR32": [Operand(-1, "imm", -1)],
            "VectorIndexB": [Operand(-1, "imm", -1)],
            "VectorIndexH": [Operand(-1, "imm", -1)],
            "VectorIndexH32b": [Operand(-1, "imm", -1)],  # ?
            "VectorIndex0": [Operand(-1, "imm", -1)],  # ?
            "barrier_op": [Operand(-1, "imm", -1)],
            "sve_incdec_imm": [Operand(-1, "imm", -1)],
            "prfop": [Operand(-1, "imm", -1)],
            "sve_elm_idx_extdup_b": [Operand(-1, "imm", -1)],
            "sve_elm_idx_extdup_h": [Operand(-1, "imm", -1)],
            "sve_elm_idx_extdup_s": [Operand(-1, "imm", -1)],
            "sve_elm_idx_extdup_d": [Operand(-1, "imm", -1)],
            "rprfop": [Operand(-1, "imm", -1)],
            "ccode": [Operand(-1, "imm", 4)],  # conditional code like LT
            "VG": [],  # conditional code like LT technically 4
        }
        decode_map.update(z_v_regs)

        if name in decode_map:
            return decode_map[name]
        print(f"unknown op: {name} please implement")
        return []


def get_env(arch: Literal["X86", "AArch64"]) -> LLVMInterface:
    assert arch in ["X86", "AArch64"]
    global _env
    if _env is None:
        _env = LLVMInterface(arch)
    return _env
