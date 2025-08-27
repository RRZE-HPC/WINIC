import os
from .comparison import db_diff, compare
from .plotting import *
from .setup import *
from .statistics import *
import argparse

# this file was mostly AI generated
ARCHES = [
    "CON",
    "WOL",
    "NHM",
    "WSM",
    "SNB",
    "IVB",
    "HSW",
    "BDW",
    "SKL",
    "SKX",
    "KBL",
    "CFL",
    "CNL",
    "CLX",
    "ICL",
    "TGL",
    "RKL",
    "ADL-P",
    "ADL-E",
    "BNL",
    "AMT",
    "GLM",
    "GLP",
    "TRM",
    "ZEN+",
    "ZEN2",
    "ZEN3",
    "ZEN4",
]

ARCH_NAMES = {
    "CON": "Conroe",
    "WOL": "Wolfdale",
    "NHM": "Nehalem",
    "WSM": "Westmere",
    "SNB": "Sandy Bridge",
    "IVB": "Ivy Bridge",
    "HSW": "Haswell",
    "BDW": "Broadwell",
    "SKL": "Skylake",
    "SKX": "Skylake-X",
    "KBL": "Kaby Lake",
    "CFL": "Coffee Lake",
    "CNL": "Cannon Lake",
    "CLX": "Cascade Lake",
    "ICL": "Ice Lake",
    "TGL": "Tiger Lake",
    "RKL": "Rocket Lake",
    "ADL-P": "Alder Lake-P",
    "ADL-E": "Alder Lake-E",
    "BNL": "Bonnell",
    "AMT": "Atom",
    "GLM": "Goldmont",
    "GLP": "Goldmont Plus",
    "TRM": "Tremont",
    "ZEN+": "Zen+",
    "ZEN2": "Zen 2",
    "ZEN3": "Zen 3",
    "ZEN4": "Zen 4",
}


def main():
    parser = argparse.ArgumentParser(description="LLVM Bench Analysis CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # setup command
    setup_parser = subparsers.add_parser("setup", help="Generate the necessary files for the analysis scripts")
    setup_parser.add_argument("llvm_build_dir", help="Path to the LLVM build directory to be used")
    setup_parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing files")
    setup_parser.add_argument(
        "--step",
        choices=["dump", "uops", "ref", "all"],
        default="all",
        help="Specify which setup step to run",
    )

    # db_diff command
    diff_parser = subparsers.add_parser("db-diff", help="Generate a diff between two databases")
    diff_parser.add_argument("db1", help="Path to first database YAML file")
    diff_parser.add_argument("db2", help="Path to second database YAML file")
    diff_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    diff_parser.add_argument("--output", default="", help="File to write a detailed diff report to")

    arch_help = "Architecture name. Supported: " + ", ".join([f"{arch}: {ARCH_NAMES[arch]}" for arch in ARCHES])

    # compare command
    compare_parser = subparsers.add_parser("compare", help="Compare database and plot results")
    compare_parser.add_argument("db", help="Path to database YAML file")
    compare_parser.add_argument("arch", choices=ARCHES, help=arch_help)
    compare_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    compare_parser.add_argument("--output", default="", help="Plot results to file")

    # plot command
    plot_parser = subparsers.add_parser("plot", help="Generate plots out of hardcoded data")
    plot_parser.add_argument("path", help="Output path")
    plot_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to plot")

    # stat command
    stat_parser = subparsers.add_parser("stat", help="Show statistics for a WINIC database")
    stat_parser.add_argument("db", help="Path to database YAML file")

    args = parser.parse_args()

    match args.command:
        case "setup":
            ref_dir = "analysis/reference-files"
            os.makedirs(ref_dir, exist_ok=True)
            if args.step in ("dump", "all"):
                gen_tblgen_dumps(args.llvm_build_dir, "llvm-project", args.force)
            if args.step in ("uops", "all", args.force):
                download_uops_database(args.force)
            if args.step in ("ref", "all", args.force):
                os.makedirs(f"{ref_dir}/X86", exist_ok=True)
                os.makedirs(f"{ref_dir}/AArch64", exist_ok=True)
                os.makedirs(f"{ref_dir}/RISCV", exist_ok=True)
                gen_quick_reference_files(f"{ref_dir}/X86.json", f"{ref_dir}/X86/", args.force)
                gen_quick_reference_files(f"{ref_dir}/AArch64.json", f"{ref_dir}/AArch64/", args.force)
                gen_quick_reference_files(f"{ref_dir}/RISCV.json", f"analysis/reference-files/RISCV/", args.force)
        case "db-diff":
            db_diff(args.db1, args.db2, args.mode, args.output)
        case "compare":
            lat_res = None
            tp_res = None
            if args.mode == "LAT" or args.mode == "BOTH":
                print("Processing Latency")
                lat_res = compare(args.db, "lat", args.arch)
            if args.mode == "TP" or args.mode == "BOTH":
                print("Processing Throughput")
                tp_res = compare(args.db, "tp", args.arch)
            if args.output != "":
                output_dir = os.path.dirname(args.output)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                plot(lat_res, tp_res, args.output, args.mode)
        case "plot":
            plot(None, None, args.path, args.mode)
        case "stat":
            count_ranges(args.db)
            count_instr_different_sublatencies(args.db)


if __name__ == "__main__":
    main()
