# Analysis of the results
Here are some scripts to compare the measurements with existing data from uops.info.
The scripts utilize llvm-tblgen json dumps and the uops.info database as xml to match instructions and compare the results.

## Generate Files
To generate the json dumps run in a llvm-build directory:
```bash
./bin/llvm-tblgen -I ../llvm/include -I ../llvm/lib/Target/X86 ../llvm/lib/Target/X86/X86.td -dump-json > X86.json
```
```bash
./bin/llvm-tblgen -I ../llvm/include -I ../llvm/lib/Target/AArch64/ ../llvm/lib/Target/AArch64/AArch64.td -dump-json > AArch64.json
```
```bash
./bin/llvm-tblgen -I ../llvm/include -I ../llvm/lib/Target/RISCV/ ../llvm/lib/Target/RISCV/RISCV.td -dump-json > RISCV.json
```


## Quick Instruction Overview
`build_ref_files.py` extracts all LLVM instruction information for each architecture.
This is useful to quickly find the operand list or other relevant information about any instruction.
Information about Processors, Features, RegisterClasses etc. can be enabled, if needed.

## Compare results
`compare.py` compares NAME results to uops.info results. Works only for x86 since uops.info only has x86 data.
Relies on uops.xml which is available at https://uops.info/instructions.xml and can be obtained using the Makefile in `reference-files`.