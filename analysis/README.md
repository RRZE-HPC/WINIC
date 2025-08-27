# Analysis
This directory contains scripts for analyzing results obtained with WINIC. The main entry point is the CLI tool.

## Quick start
Run
```bash
python -m analysis.cli setup <llvm_build_dir>
```
to generate the necessary files for this script collection. A llvm build directory is required.

Then run 
```bash
python -m analysis.cli compare <db.yaml> <arch> --output plot.svg
```
to compare a WINIC database to uops.info. A plot with the results will be written to plot.svg

## Usage
Run the CLI with:

```bash
python -m analysis.cli <command> [options]
```

## Commands

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


### db-diff
Generate a diff between two WINIC YAML files.

**Usage:**
```bash
python -m analysis.cli db-diff <db1.yaml> <db2.yaml> [--mode TP|LAT|BOTH] [--output <file>]
```
- `db1`, `db2`: Paths to the WINIC database files.
- `--mode`: Compare throughput (`TP`), latency (`LAT`), or both (`BOTH`). Default: BOTH.
- `--output`: Write a detailed diff report to a file.

### compare
Compare a database against values from uops.info and plot the results. This is only available for x86 since uops.info only has x86 data.

**Usage:**
```bash
python -m analysis.cli compare <db.yaml> <arch> [--mode TP|LAT|BOTH] [--output <file>]
```
- `db`: Path to the database file.
- `arch`: Uops architecture name (see supported list below).
- `--mode`: Compare throughput, latency, or both. Default: BOTH.
- `--output`: Plot results to a file.

#### Supported Architectures
- CON: Conroe
- WOL: Wolfdale
- NHM: Nehalem
- WSM: Westmere
- SNB: Sandy Bridge
- IVB: Ivy Bridge
- HSW: Haswell
- BDW: Broadwell
- SKL: Skylake
- SKX: Skylake-X
- KBL: Kaby Lake
- CFL: Coffee Lake
- CNL: Cannon Lake
- CLX: Cascade Lake
- ICL: Ice Lake
- TGL: Tiger Lake
- RKL: Rocket Lake
- ADL-P: Alder Lake-P
- ADL-E: Alder Lake-E
- BNL: Bonnell
- AMT: Atom
- GLM: Goldmont
- GLP: Goldmont Plus
- TRM: Tremont
- ZEN+: Zen+
- ZEN2: Zen 2
- ZEN3: Zen 3
- ZEN4: Zen 4

### plot
Generate plots from hardcoded data. This is mostly useful for developing new plotting scripts.

**Usage:**
```bash
python -m analysis.cli plot <output_path> [--mode TP|LAT|BOTH]
```
- `output_path`: Path to save the plot.
- `--mode`: Plot throughput, latency, or both. Default: BOTH.

### stat
Generate statistics for a WINIC database. Extracts how many TP/LAT entries are ranges vs exact values as well as the number of instructions with different latency values for different operand combinations.

**Usage:**
```bash
python -m analysis.cli stat <db.yaml>
```
- `db`: Path to the database file.


## Reference Files
The `ref` setup step will generate useful files in the `analysis/reference-files/<arch>` directories. The `Instruction` file, for example contains all information LLVM has about each instruction of the given architecture.
