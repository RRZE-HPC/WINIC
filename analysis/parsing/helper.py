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
