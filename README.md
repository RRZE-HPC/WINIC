
# Introduction

WINIC is a platform-independent automated micro-benchmarking tool. It currently works for x86 and ARM on Linux.
WINIC can automatically determine latency and throughput values for all instructions the given CPU supports.

## Limitations
WINIC currently cannot measure: 
- instructions accessing memory (this will be added in the future)
- branches, returns, system calls

# Download and Build
WINIC is relying on LLVM and clang to generate and assemble benchmarks. Use `setup.sh` after cloning this repository to automatically download and build LLVM aswell as NAME. To manage multiple builds e.g. for multiple platforms in an HPC context specify `--dir <buildName>` to build a version of LLVM into ./llvm-build-buildName and WINICinto ./build-buildName.

# Usage
To calculate throughput and latency WINIC needs the clock-frequency to be fixed e.g. by using [likwid-setFrequencies](https://github.com/RRZE-HPC/likwid/wiki/likwid-setFrequencies). Once the frequency is fixed you can use WINIC as follows: 
```bash
./winic -f <frequency> MODE [options]
```
## Available modes:
### LAT/TP:
Measure latencies or throughputs.
By default WINIC measures all available instructions and generates a .yaml file with the results. Additionally a `report_mode_timestamp.txt` is generated providing additional information about how the values were obtained and warnings about unusual results. The runtime of a full run strongly depends on the architecture.

|Mode|Arch|Approx. Time|
|----|----|----|
|TP|x86|1h|
|LAT|x86|1.5h|
|TP|RISCV|7min|
|LAT|RISCV|10min|

To measure only a range of opcodes, use `--minOpcode` and `--maxOpcode`.

To measure single instructions add one or more `-i <LLVM_INSTRUCTION_NAME>` options.

### MAN
In manual mode, WINIC can execute arbitrary altered benchmark functions.
To run a function called "tp" from `file.s` and calculate the cycles per instruction assuming the loop has 12 instructions do
```bash
winic -f <frequency> MAN --path file.s --funcName tp --nInst 12
```

There are always cases where WINIC doesn't produce correct data. To do a custom benchmark for an instruction, first run WINIC in TP or LAT mode with `-i <LLVM_INSTRUCTION_NAME>`. This will output all `.s` files generated for the benchmark to `asm/` and an `assembler_out.log`. The `.s` files can then be modified and executed using the MAN-mode.

## Updating existing database
By default TP and LAT mode generate a db_timestamp.yaml file with the results. Use `--output <file.yaml>` to specify a custom path instead. If the file already exists the values obtained during the run will overwrite the existing ones, all other values will be left unchanged. This works with single instructions aswell as full TP/LAT runs. A standard workflow therefore would be to do a TP run generating a database and then a LAT run updating it.

## Helper instructions
WINIC automatically uses helper instructions to:
- break dependencies between instructions to measure throughput
- introduce dependencies between instructions to measure latency

All uses of helper instructions are logged in `report_timestamp.txt`.\
If an instruction would need a helper but none can be found, WINIC will fail and report "ERROR_NO_HELPER".\
WINIC can only use instructions as helper if they were measured in the current run which is a problem when trying to measure single instructions.
The solution is to first do a full run and look up the dependencies of the instruction in the report, then the measurement can be reproduced by supplying all dependencies alongside the instruction using the `-i <LLVM_INSTRUCTION_NAME>` option. \
Note that currently `--output` does NOT load the values into the internal working databases so the information read from there can NOT be used as helpers.

## Analysis/Reference files
There are scripts in `analysis` to compare the measurements on x86 with uops.info aswell as to generate useful reference files which contain comprehensive information about instructions, operands, registers etc. from LLVM. For more details refer to `analysis/README.md`.
