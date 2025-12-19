from typing import List
from analysis.globals import Operand


# registers get width -1 if no value known and 0 if any value allowed (e.g. scalable)
def get_aarch_operands(name: str, shapeHint: str = "") -> List[Operand]:
    z_v_regs = {
        "V64": [Operand(-1, "reg", 64 ,metadata={"prefix": "v"})],
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
        "VecListFour16b": [Operand(-1, "reg", 0), Operand(-1, "reg", 0), Operand(-1, "reg", 0), Operand(-1, "reg", 0)],
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
    # print(f"unknown op: {name} please implement")
    return []


def get_register_width(reg_name: str) -> int | None:
    """Return the bit-width of the given LLVM register name for x86.

    Returns:
        int: Width in bits, or None if unknown.
    """
    # AI generated
    # Normalize name (in case someone passes lowercase)
    reg = reg_name.upper()

    # Specific register widths
    known_widths = {
        # FLAGS
        "EFLAGS": None,  # 32,
        "RFLAGS": 64,
        "MXCSR": 32,
        # IP registers
        "IP": 16,
        "EIP": 32,
        "RIP": 64,
        # Segment registers
        "CS": 16,
        "DS": 16,
        "ES": 16,
        "FS": 16,
        "GS": 16,
        "SS": 16,
        # Base addresses
        "FS_BASE": 64,
        "GS_BASE": 64,
        "SSP": 64,
        # MMX
        **{f"MM{i}": 64 for i in range(8)},
        # "MM0": 64, "MM1": 64, "MM2": 64, "MM3": 64, "MM4": 64, "MM5": 64, "MM6": 64, "MM7": 64,
        # FPU registers
        "ST0": 80,
        "ST1": 80,
        "ST2": 80,
        "ST3": 80,
        "ST4": 80,
        "ST5": 80,
        "ST6": 80,
        "ST7": 80,
        "FP0": 80,
        "FP1": 80,
        "FP2": 80,
        "FP3": 80,
        "FP4": 80,
        "FP5": 80,
        "FP6": 80,
        "FP7": 80,
        "FPCW": 16,
        "FPSW": 16,
        # AVX mask registers
        **{f"K{i}": 64 for i in range(8)},
        # Debug & control registers (assume full machine word)
        # **{f"DR{i}": 64 for i in range(16)},
        **{f"CR{i}": 64 for i in range(16)},
        # # Tile registers (AMX)
        # **{f"TMM{i}": 8192 for i in range(8)},
        # "TMMCFG": 64,
    }

    # If it's directly known
    if reg in known_widths:
        return known_widths[reg]
    k_regs = {f"K{i}": 64 for i in range(8)}
    if reg in k_regs:
        return 64

    # Register suffix patterns
    if reg.endswith("B"):  # 8-bit (low)
        return 8
    if reg.endswith("BH"):  # 8-bit (high byte)
        return 8
    if reg.endswith("L"):  # 8-bit (low byte)
        return 8
    if reg.endswith("H"):  # High byte (usually 8-bit)
        if len(reg) <= 3:  # AH, BH, etc.
            return 8
        if reg.endswith("WH"):  # e.g. R10WH
            return 16
        return 8
    if reg.endswith("W"):  # 16-bit
        return 16
    if reg in {"AX", "BX", "CX", "DX", "SI", "DI", "SP", "BP", "IP"}:
        return 16
    if reg.endswith("D"):  # 32-bit
        return 32
    if reg.startswith("E") and len(reg) == 3:  # EAX, EBX, etc.
        return 32
    if reg.startswith("R") and reg[1:].isdigit():  # R8, R10, etc.
        return 64
    if reg.startswith("R") and len(reg) >= 3 and reg[2] not in "BDWH":  # RAX, RBP, etc.
        return 64
    if reg in {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP"}:
        return 64

    # SIMD vector registers
    if reg.startswith("XMM"):
        return 128
    if reg.startswith("YMM"):
        return 256
    if reg.startswith("ZMM"):
        return 512

    # print(f"unhandled register: {reg_name}")
    return None  # Unknown
