# Analysis
This directory contains scripts for analyzing results obtained with WINIC. The main entry point is the CLI tool.

## Quick start
Install the necessary python packages in `requirements.txt`.
Run
```bash
python -m analysis.cli setup <llvm_build_dir>
```
to generate the necessary files for this script collection. An LLVM build directory is required.

Then run 
```bash
python -m analysis.cli compare uops <arch> <db.yaml>
```
to compare a WINIC database to uops.info and plot the result.

## Usage
Run the CLI with:

```bash
python -m analysis.cli <command> [subcommand] [options]
```

### setup
This script collection needs the uops.info database as well as llvm-tblgen dumps to work. The `setup` command downloads and generates all necessary files automatically. For the tblgen dumps it needs the `llvm-tblgen` binary built with LLVM, therefore a llvm build directory must be supplied. Refer to the main README for how to build LLVM for WINIC.

**Usage:**
```bash
python -m analysis.cli setup <llvm_build_dir> [--step dump|uops|ref|all] [--force]
```
- `llvm_build_dir`: Path to your LLVM build directory.
- `--step`: Specify which setup step to run:
  - `dump`: Generate tblgen dumps.
  - `uops`: Download uops.info database.
  - `ref`: Extract reference files from dumps.
  - `all`: Run all setup steps (default).
- `--force`: By default a step will be skipped if the files it produces already exist. This flag will overwrite existing files.


### diff
Compare two WINIC YAML files.

**Usage:**
```bash
python -m analysis.cli diff <db1.yaml> <db2.yaml> [--mode TP|LAT|BOTH] [--verbose -v]
```
- `db1`, `db2`: Paths to the WINIC database files.
- `--mode`: Compare throughput (`TP`), latency (`LAT`), or both (`BOTH`). Default: BOTH.
- `--verbose`: Report every individual change.

### compare to uops / documentation
Compare WINIC results to results from uops.info (x86 only) or selected documentation (zen4, neoverse-v2).

**Usage:**
```bash
python -m analysis.cli compare <uops / docs> <arch> <db.yaml> [--mode TP|LAT|BOTH] [--output <file>]
```
- `arch`: Architecture name (see supported list below).
- `db`: Path to the database file.
- `--mode`: Compare throughput, latency, or both. Default: BOTH.
- `--verbose`: Enable verbose output.

#### Supported Architectures for uops
<table>
<tr>
<td valign="top">
  
| Shorthand | Architecture |
|---|---|
| CON | Conroe |
| WOL | Wolfdale |
| NHM | Nehalem |
| WSM | Westmere |
| SNB | Sandy Bridge |
| IVB | Ivy Bridge |
| HSW | Haswell |
| BDW | Broadwell |
| SKL | Skylake |
| SKX | Skylake-X |
| KBL | Kaby Lake |
| CFL | Coffee Lake |
| CNL | Cannon Lake |
| CLX | Cascade Lake |

</td>
<td valign="top">

| Shorthand | Architecture |
|---|---|
| ICL | Ice Lake |
| TGL | Tiger Lake |
| RKL | Rocket Lake |
| ADL-P | Alder Lake-P |
| ADL-E | Alder Lake-E |
| BNL | Bonnell |
| AMT | Atom |
| GLM | Goldmont |
| GLP | Goldmont Plus |
| TRM | Tremont |
| ZEN+ | Zen+ |
| ZEN2 | Zen 2 |
| ZEN3 | Zen 3 |
| ZEN4 | Zen 4 |
</td>
</tr>
</table>


#### Supported Architectures for docs
| Shorthand | Architecture |
|---|---|
| V2 | Neoverse v2 |
| ZEN4 | Zen 4 |

### compare to exegesis / OSACA
Compare WINIC results to llvm-exegesis output.

**Usage:**
```bash
python -m analysis.cli compare <exegesis / osaca> <db_winic> <db_other> [db_exegesis ...] [--mode TP|LAT|BOTH] [--output <file>]
```
- `db_winic`: Path to the WINIC database file.
- `db_other`: exegesis/OSACA database.
- `db_exegesis`: Paths to the exegesis YAML files (can specify multiple).
- `--mode`: Compare throughput, latency, or both. Default: BOTH.
- `--verbose`: Enable verbose output.


### plot
Generate plots from hardcoded data. This is mostly useful for developing new plotting scripts.

**Usage:**
```bash
python -m analysis.cli plot <output_path> [--mode TP|LAT|BOTH]
```
- `output_path`: Path to save the plot.
- `--mode`: Plot throughput, latency, or both. Default: BOTH.

### stat
Generate statistics for a WINIC database.

**Usage:**
```bash
python -m analysis.cli stat <type> <db.yaml> [options]
```
**Types:**
- `ranges`: Count how many instructions have ranges instead of exact values for TP/LAT.
- `sublatencies`: Count how many instructions have distinct sublatency values for different operand combinations.
- `distribution`: Plot the distribution of TP/LAT values.


## Reference Files
The `ref` setup step will generate useful files in the `analysis/reference-files/<arch>` directories. The `Instruction` file, for example contains all information LLVM has about each instruction of the given architecture.
