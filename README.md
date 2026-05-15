
# Introduction
WINIC is a platform-independent automated micro-benchmarking tool. It currently supports x86, ARM and RISC-V on Linux.
WINIC can automatically determine latency and throughput values for all instructions the given CPU supports.

## Limitations
WINIC currently cannot measure: 
- instructions accessing memory (this will be added in the future)
- branches, returns, system calls and privileged instructions

## Benchmarking strategy
For a given instruction form, WINIC either generates a kernel that allows the CPU to parallelize execution for measuring throughput, or one that forces sequential execution for measuring latency. The kernel generated is executed in a loop and the total runtime is measured. The cycles needed per executed instruction is calculated using only the clock frequency and the number of times the instruction was executed.

# Download and Build
WINIC uses LLVM and clang to generate and assemble benchmarks. Use `setup.sh` after cloning this repository to automatically download and build LLVM and WINIC. To manage multiple builds e.g. for multiple platforms in an HPC context specify `--dir <buildName>` to build a version of LLVM into ./llvm-build-buildName and WINIC into ./build-buildName.

# Usage
To calculate throughput and latency WINIC needs the clock-frequency to be fixed e.g. by using [likwid-setFrequencies](https://github.com/RRZE-HPC/likwid/wiki/likwid-setFrequencies). Once the frequency is fixed use WINIC as follows: 
```bash
./winic -f <frequency> [options] MODE [mode-specific-options]
```

## Global Options
| Option | Description | Default |
|--------|-------------|---------|
| `-f,--frequency` | Frequency in GHz (required) | - |
| `-d,--debug` | Enable debug output | false |
| `-c,--cpu` | CPU model, only needed if LLVM cannot detect it | - |
| `-m,--march` | Architecture, only needed if LLVM cannot detect it | - |
| `-v,--version` | Show version | - |

## Available modes:
### TP/LAT:
Measure latencies or inverse throughputs.
By default WINIC measures all available instructions and generates a .yaml file with the results. Additionally a `report_{MODE}_{TIMESTAMP}` is generated providing additional information about how the values were obtained and warnings about unusual results. The runtime of a full run strongly depends on the architecture, here some rough estimates:

|Architecture|Runtime TP|Runtime LAT|
|----|----|----|
|x86|25 min - 3h|40 min - 3h|
|AArch64|5 min|25 min|
|RISCV|10 min|10 min|

### TP/LAT Options
| Option | Description | Default |
|--------|-------------|---------|
| `-i,--instruction` | Measure specific instructions by LLVM instruction name. This option can take multiple names or regular expressions. For example, to measure all variants of SSE/AVX fused-multiply-add instructions use `-i VFMADD.*`| - |
| `-o,--output` | Path to the .yaml file to save the results to. If the file already exists it will be updated (see [updating a database](#updating-a-database)) . If no file is specified, a timestamped one will be generated. If set to /dev/null no file will be generated. | - |
| `--register-init-value V` | Load `V` into all registers used before every benchmark run. Accepts decimal, octal with prefix 0 or hexadecimal with prefix 0x | 4 |
| `--immediate-value V` | Set all immediates to `V`. Accepts decimal, octal with prefix 0 or hexadecimal with prefix 0x | 7 |
| `--runs N` | Repeat each measurement `N` times and take the minimum runtime | 4 |
| `--no-report` | Don't generate report file | false |
| `--output-asm` | Write the generated asm files to `asm/` (clears the directory at the start of the run) | false |
| `--include-x87-fp` | By default x87 floating point instructions are excluded, as they are deprecated and consume a lot of time on architectures that emulate them. Use this flag to include them | false |
| `--keep-empty-entries` | Include instructions in the output even if they do not have any values | false |
| `--min-opcode` | Minimum LLVM opcode number to measure (this is mostly useful for development) | 0 |
| `--max-opcode` | Maximum LLVM opcode number to measure (this is mostly useful for development) | max opcode |

### MAN
In manual mode, WINIC can execute arbitrary benchmark functions.
To run a function called `tp` from `file.s` and calculate the cycles per instruction assuming the loop has 12 instructions do
```bash
winic -f <frequency> MAN --path file.s --func-name tp --num-instructions 12
```

#### MAN Options
| Option | Description | Default |
|--------|-------------|---------|
| `-p,--path` | Assembly file path (required) | - |
| `--func-name` | Function to benchmark (required) | - |
| `-n,--num-instructions` | Number of instructions in loop (required) | - |
| `--init-name` | Initialization function | - |
| `--runs N` | Repeat each measurement `N` times and take the minimum runtime | 4 |

There are always cases where WINIC doesn't produce correct data. To do a custom benchmark for an instruction, first run WINIC in TP or LAT mode with `-i <LLVM_INSTRUCTION_NAME> --output-asm`. This will output all `.s` files generated for the benchmark to `asm/` and an `assembler_out.log`. The `.s` files can then be modified and executed using the MAN-mode.

## Updating a database
By default TP and LAT mode generate a `db_{TIMESTAMP}.yaml` file with the results. Use `-o/--output <file.yaml>` to specify a custom path instead. If the file already exists the values obtained during the run will overwrite the existing ones according to the following rules:
- all new non-null values will overwrite existing values
- new null values will not overwrite existing values
- all existing values will be left unchanged if no new value was obtained

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
The `analysis/` python module can be used to compare the results with various other sources, or to generate useful reference files which contain comprehensive information about instructions, operands, registers etc. from LLVM. For more details refer to `analysis/README.md`.
