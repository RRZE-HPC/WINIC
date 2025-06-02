
# Introduction

NAME is a platform-independent automated micro-benchmarking tool. It currently works for x86 and ARM on Linux.
NAME can automatically determine latency and throughput values for all instructions the given CPU supports.

## Limitations
NAME currently cannot measure: 
- instructions accessing memory (this will be added in the future)
- branches, returns, system calls

# Download and Build
NAME is relying on LLVM and clang to generate and assemble benchmarks. Use `setup.sh` after cloning this repository to automatically download and build LLVM aswell as NAME. To manage multiple builds e.g. for multiple platforms in an HPC context specify `--dir <buildName>` to build a version of LLVM into ./llvm-build-buildName and NAME into ./build-buildName.

# Usage
To calculate throughput and latency NAME needs the clock-frequency to be fixed e.g. by using [likwid-setFrequencies](https://github.com/RRZE-HPC/likwid/wiki/likwid-setFrequencies). Once the frequency is fixed you can use NAME as follows: 
```bash
./NAME -f <frequency> MODE [options]
```
## Available modes:
### LAT/TP:
Measure latencies or throughputs.
By default NAME measures all available instructions and generates a .yaml file with the results. Additionally a `report_mode_timestamp.txt` is generated providing additional information about how the values were obtained and warnings about unusual results. The runtime of a full run strongly depends on the architecture.

|Mode|Arch|Approx. Time|
|----|----|----|
|TP|x86|1h|
|LAT|x86|1.5h|
|TP|RISCV|7min|
|LAT|RISCV|10min|

To measure only a range of opcodes, use `--minOpcode` and `--maxOpcode`.

To measure single instructions add one or more `-i <LLVM_INSTRUCTION_NAME>` options.

### MAN
In manual mode, NAME can execute arbitrary altered benchmark functions.
To run a function called "tp" from `debug.s` and calculate the cycles per instruction assuming the loop has 12 instructions do
```bash
NAME -f <frequency> MAN --path debug.s --funcName tp --nInst 12
```

There are always cases where NAME doesn't produce correct data. To do a custom benchmark for an instruction, first run NAME in TP or LAT mode with `-i <LLVM_INSTRUCTION_NAME>`. This will output an `assembler_out.log` and `debug.s` file generated for the benchmark. The `debug.s` file can then be modified and executed using the MAN-mode.

## Updating existing database
By default TP and LAT mode generate a db_timestamp.yaml file with the results. Use `--updateDatabase <file.yaml>` to update an existing database instead. This works with single instructions aswell as full TP/LAT runs. A standard workflow therefore would be to do a TP run generating a database and then a LAT run updating it.

## Helper instructions
NAME automatically uses helper instructions to:
- break dependencies between instructions to measure throughput
- introduce dependencies between instructions to measure latency

All uses of helper instructions are logged in `report_timestamp.txt`.\
If an instruction would need a helper but none can be found, NAME will fail and report "ERROR_NO_HELPER".\
NAME can only use instructions as helper if they were measured in the current run which is a problem when trying to measure single instructions.
The solution is to first do a full run and look up the dependencies of the instruction in the report, then the measurement can be reproduced by supplying all dependencies alongside the instruction using the `-i <LLVM_INSTRUCTION_NAME>` option. \
Note that currently `--updateDatabase` does NOT load the values into the internal working databases so the information read from there can NOT be used as helpers.
