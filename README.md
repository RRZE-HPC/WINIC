
# Introduction

WINIC is a platform-independent automated micro-benchmarking tool. It currently supports x86, ARM and RISC-V on Linux.
WINIC can automatically determine latency and throughput values for all instructions the given CPU supports.

## Limitations
WINIC currently cannot measure: 
- instructions accessing memory (this will be added in the future)
- branches, returns, system calls and privileged instructions

# Download and Build
WINIC is relying on LLVM and clang to generate and assemble benchmarks. Use `setup.sh` after cloning this repository to automatically download and build LLVM and WINIC. To manage multiple builds e.g. for multiple platforms in an HPC context specify `--dir <buildName>` to build a version of LLVM into ./llvm-build-buildName and WINIC into ./build-buildName.

# Usage
To calculate throughput and latency WINIC needs the clock-frequency to be fixed e.g. by using [likwid-setFrequencies](https://github.com/RRZE-HPC/likwid/wiki/likwid-setFrequencies). Once the frequency is fixed you can use WINIC as follows: 
```bash
./winic -f <frequency> MODE [options]
```
## Available modes:
### LAT/TP:
Measure latencies or throughputs.
By default WINIC measures all available instructions and generates a .yaml file with the results. Additionally a `report_{MODE}_{TIMESTAMP}` is generated providing additional information about how the values were obtained and warnings about unusual results. The runtime of a full run strongly depends on the architecture.

|Architectrure|Runtime TP|Runtime LAT|
|----|----|----|
|x86|23 min|40 min|
|AArch64|23 min|17 min|
|RISCV|8 min|9 min|


To measure only a range of opcodes, use `--minOpcode` and `--maxOpcode`. This is mostly useful for debugging and development.

To measure single instructions add one or more `-i <LLVM_INSTRUCTION_NAME>` options. WINIC now also supports regular expressions to specify groups of instructions.
To measure e.g. the latency of all variants of SSE/AVX fused-multiply-add instructions use:
```bash
winic -f <frequency> LAT -o file.yaml -i VFMADD.* 
```

By default all registers used by the benchmark kernels are initialized to a hardcoded value (currently 4). Specify `--regInit <initValue>` to use another value instead. This option takes decimal, octal values with prefix `0` or hexadecimal values with prefix `0x`.

For running custom benchmarks WINIC writes the files generated to `asm/` if the total number of instructions is 10 or less. To force WINIC to output any number of instructions use the `--outputASM` flag. WARNING: using this option on full runs will generate thousands of files.

By default x87 floating point instructions are excluded, as they are deprecated and consume a lot of time on architectures that emulate them. Use the `--x87FP` flag to include them.

### MAN
In manual mode, WINIC can execute arbitrary altered benchmark functions.
To run a function called "tp" from `file.s` and calculate the cycles per instruction assuming the loop has 12 instructions do
```bash
winic -f <frequency> MAN --path file.s --funcName tp --nInst 12
```

There are always cases where WINIC doesn't produce correct data. To do a custom benchmark for an instruction, first run WINIC in TP or LAT mode with `-i <LLVM_INSTRUCTION_NAME>`. This will output all `.s` files generated for the benchmark to `asm/` and an `assembler_out.log`. The `.s` files can then be modified and executed using the MAN-mode.

## Updating existing database
By default TP and LAT mode generate a `db_{TIMESTAMP}.yaml` file with the results. Use `-o/--output <file.yaml>` to specify a custom path instead. If the file already exists the values obtained during the run will overwrite the existing ones according to the following rules:
- all new non-null values will overwrite existing values
- new null values will not overwrite existing values
- all existing values will be left unchanged if no new value was generated

Updating the database works with single instructions as well as full TP/LAT runs. A standard workflow therefore would be to do a TP run generating a database and then a LAT run updating it.

## Helper instructions
WINIC automatically uses helper instructions to:
- break dependencies between instructions to measure throughput
- introduce dependencies between instructions to measure latency

All uses of helper instructions are logged in `report_{MODE}_{TIMESTAMP}`.\
If an instruction would need a helper but none can be found, WINIC will fail and report "ERROR_NO_HELPER".\
WINIC can only use instructions as helper if they were measured in the current run which is a problem when trying to measure single instructions.
The solution is to first do a full run and look up the dependencies of the instruction in the report, then the measurement can be reproduced by supplying all dependencies alongside the instruction using the `-i <LLVM_INSTRUCTION_NAME>` option. \
Note that currently `--output` does NOT load the values into the internal working databases so the information read from there can NOT be used as helpers.

## Analysis/Reference files
There are scripts in `analysis` to compare the measurements on x86 with uops.info or to generate useful reference files which contain comprehensive information about instructions, operands, registers etc. from LLVM. For more details refer to `analysis/README.md`.

