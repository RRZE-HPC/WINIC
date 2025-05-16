
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
./NAME MODE -f <frequency> [options]
```
For MODE use "TP" to measure throughputs or "LAT" to measure latencies.

By default NAME measures all available instructions and generates a .yaml file with the results. This output is directly compatible to [OSACA](https://github.com/RRZE-HPC/OSACA) for which NAME was developed. Additionally a `report_Date.log` is generated providing additional information about how the values were obtained and warnings about unusual results.

To measure single instructions add one or more `-i LLVM_INSTRUCTION_NAME` options. In single instruction mode a debug.s file is generated which contains the assembly code generated for the benchmark.

## Helper instructions

NAME automatically uses helper instructions to:
- break dependencies between instructions to measure throughput
- introduce dependencies between instructions to measure latency

However for this to work properly, the results of the "helper" instructions need to be available. If they are not, NAME will fail and report "ERROR_NO_HELPER".
This is a problem when trying to measure single instructions.
The solution is to first do a full run and look up in the report, which instructions have which other instructions as dependency, then the measurement can be reproduced by supplying all dependencies alongside the instruction using the `-i LLVM_INSTRUCTION_NAME` CLI option.