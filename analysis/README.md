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

##' CLI Structure

The CLI uses a hierarchical command structure. The table below shows all available commands, subcommands, their arguments, and options.

| Command | Subcommand | Arguments | Options | Description |
|---------|------------|-----------|---------|-------------|
| `setup` | | `<llvm_build_dir>` | `--step {dump,uops,ref,all}`, `--force` | Generate necessary files for analysis (uops database, LLVM tblgen dumps, reference files) |
| `diff` | | `<db1.yaml> <db2.yaml>` | `--mode {TP,LAT,BOTH}`, `--verbose` | Compare two WINIC YAML databases |
| `compare` | | | | Compare WINIC database against external sources |
| | `uops` | `<arch> <db.yaml>` | `--mode {TP,LAT,BOTH}`, `--output <file>` | Compare to uops.info database (x86 only) |
| | `docs` | `<arch> <db.yaml>` | `--mode {TP,LAT,BOTH}`, `--output <file>` | Compare to architecture documentation |
| | `exegesis` | `<db_winic> <db_exegesis> [<db_exegesis> ...]` | `--mode {TP,LAT,BOTH}`, `--output <file>` | Compare to llvm-exegesis output |
| | `osaca` | `<db_winic> <db_osaca>` | `--mode {TP,LAT,BOTH}`, `--output <file>` | Compare to OSACA database |
| `plot` | | `<output_path>` | `--mode {TP,LAT,BOTH}` | Generate plots from hardcoded data |
| `stat` | | | | Generate statistics for WINIC database |
| | `ranges` | `<db.yaml>` | `--verbose` | Count instructions with range vs exact TP/LAT values |
| | `sublatencies` | `<db.yaml>` | `--verbose` | Count instructions with distinct sublatency values |
| | `distribution` | `<db.yaml>` | | Plot distribution of TP/LAT values |

### setup
This script collection needs the uops.info database as well as llvm-tblgen dumps to work. The `setup` command downloads and generates all necessary files automatically. For the tblgen dumps it needs the `llvm-tblgen` binary built with LLVM, therefore a llvm build directory must be supplied. Refer to the main README for how to build LLVM for WINIC.
**steps**
- `dump`: Generate tblgen dumps.
- `uops`: Download uops.info database.
- `ref`: Extract reference files from dumps.
- `all`: Run all setup steps (default).
By default a step will be skipped if the files it produces already exist. The `--force` flag will overwrite existing files.


### compare to uops / documentation
To have a general approach for comparing to those sources the rules are:
For a WINIC instruction we search for the equivalent in the other source by
- matching the asm name
- if available checking operand number, types and metadata

If the information is not sufficient to identify one exact entry, we combine the results of the candidates into a set of TP/LAT metrics.
To keep the stats comparable across sources, the operand based latencies are *not* associated to each other even if the source would provide sufficient information to do so. Therefore the operand based latencies of the WINIC result are also combined to a set of values.
Then the instruction is classified as either a match, partial match or no match.

- For a full match, the set of values of one source must be a subset of the other.
- For a partial match, the two sets have to intersect.
- If the sets do not intersect the result is classified as no match.

Those set comparisons are done separately for throughput and latency values.

#### Supported Architectures for uops.info
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
| ZEN5 | Zen 5 |
</td>
</tr>
</table>


#### Supported Architectures for docs
| Shorthand | Architecture |
|---|---|
| V2 | Neoverse v2 |
| ZEN4 | Zen 4 |


## Reference Files
The `ref` setup step will generate useful files in the `analysis/reference-files/<arch>` directories. The `Instruction` file, for example contains all information LLVM has about each instruction of the given architecture.
