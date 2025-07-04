# Analysis
Here are some scripts to compare the measurements with existing data from uops.info.
The scripts utilize llvm-tblgen json dumps and the uops.info database as xml to match instructions and compare the results.

## Generate Files
To generate the json dumps run in a llvm-build directory:
```bash
./bin/llvm-tblgen -I ../llvm-project/llvm/include -I ../llvm-project/llvm/lib/Target/X86 ../llvm-project/llvm/lib/Target/X86/X86.td -dump-json > ../analysis/reference-files/X86.json
```
```bash
./bin/llvm-tblgen -I ../llvm-project/llvm/include -I ../llvm-project/llvm/lib/Target/AArch64 ../llvm-project/llvm/lib/Target/AArch64/AArch64.td -dump-json > ../analysis/reference-files/AArch64.json
```
```bash
./bin/llvm-tblgen -I ../llvm-project/llvm/include -I ../llvm-project/llvm/lib/Target/RISCV ../llvm-project/llvm/lib/Target/RISCV/RISCV.td -dump-json > ../analysis/reference-files/RISCV.json
```
and execute `gen_ref_files.py` which will download `uops.xml` (available at https://uops.info/instructions.xml).

## Compare results
`compare.py` compares WINICs results to uops.info results. Works only for x86 since uops.info only has x86 data.
Relies on `X86.json` and `uops.xml`.

## Quick Instruction Overview
`gen_ref_files.py` also extracts all LLVM instruction information for each architecture.
This is useful to quickly find the operand list or other relevant information about any instruction.
Depends on `X86.json`, `AArch64.json` and `RISCV.json`.
