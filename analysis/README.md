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
python -m analysis.cli compare uops <arch> <db.yaml> --output plot.svg
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
- `--output`: Plot results to a file.

#### Supported Architectures for uops
<table>
<tr>
<td valign="top">
<table>
<tr><th>Shorthand</th><th>Architecture</th></tr>
<tr><td>NHM   </td><td> Nehalem</td></tr>
<tr><td>WSM   </td><td> Westmere</td></tr>
<tr><td>SNB   </td><td> Sandy Bridge </td><td>
<tr><td>IVB   </td><td> Ivy Bridge </td><td>
<tr><td>HSW   </td><td> Haswell </td><td>
<tr><td>BDW   </td><td> Broadwell </td><td>
<tr><td>SKL   </td><td> Skylake </td><td>
<tr><td>SKX   </td><td> Skylake-X </td><td>
<tr><td>KBL   </td><td> Kaby Lake </td><td>
<tr><td>CFL   </td><td> Coffee Lake </td><td>
<tr><td>CNL   </td><td> Cannon Lake </td><td>
<tr><td>CLX   </td><td> Cascade Lake </td><td>
<tr><td>ICL   </td><td> Ice Lake </td><td>
</table>
</td>

<td valign="top">
<table>
<tr><th>Shorthand</th><th>Architecture</th></tr>
<tr><td>TGL   </td><td> Tiger Lake </td><td>
<tr><td>RKL   </td><td> Rocket Lake </td><td>
<tr><td>ADL-P </td><td> Alder Lake-P </td><td>
<tr><td>ADL-E </td><td> Alder Lake-E </td><td>
<tr><td>BNL   </td><td> Bonnell </td><td>
<tr><td>AMT   </td><td> Atom </td><td>
<tr><td>GLM   </td><td> Goldmont </td><td>
<tr><td>GLP   </td><td> Goldmont Plus </td><td>
<tr><td>TRM   </td><td> Tremont </td><td>
<tr><td>ZEN+  </td><td> Zen+ </td><td>
<tr><td>ZEN2  </td><td> Zen 2 </td><td>
<tr><td>ZEN3  </td><td> Zen 3 </td><td>
<tr><td>ZEN4  </td><td> Zen 4 </td><td>
</table>
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
- `--output`: Plot results to a file.


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
