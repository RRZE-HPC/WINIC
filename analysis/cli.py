import os
from analysis.plotting import *
from analysis.setup import *
from analysis.statistics import *
import argparse

UOPS_ARCHES = [
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

DOCS_ARCHES = ["V2", "ZEN4"]

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
    "V2": "Neoverse v2",
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

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Generate a diff between two databases")
    diff_parser.add_argument("db1", help="Path to first database YAML file")
    diff_parser.add_argument("db2", help="Path to second database YAML file")
    diff_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    diff_parser.add_argument("--verbose", "-v", action="store_true", help="Report every individual change")

    arch_help = "Architecture name. Supported: " + ", ".join([f"{arch}: {ARCH_NAMES[arch]}" for arch in UOPS_ARCHES])

    # compare command
    compare_parser = subparsers.add_parser("compare", help="Compare database and plot results")
    sub_compare_parser = compare_parser.add_subparsers(dest="compare_source")

    # compare to uops
    uops_c_parser = sub_compare_parser.add_parser("uops", help="Compare to results from uops.info")
    uops_c_parser.add_argument("arch", choices=UOPS_ARCHES, help=arch_help)
    uops_c_parser.add_argument("db", help="Path to database YAML file")
    uops_c_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    uops_c_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    uops_c_parser.add_argument("--instruction", "-i", help="Debug the matching algorithm for one WINIC instruction")

    # compare to docs
    docs_c_parser = sub_compare_parser.add_parser("docs", help="Compare to documentation")
    docs_c_parser.add_argument("arch", choices=DOCS_ARCHES, help=arch_help)
    docs_c_parser.add_argument("db", help="Path to database YAML file(s)")
    docs_c_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    docs_c_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    # compare to exegesis
    docs_c_parser = sub_compare_parser.add_parser("exegesis", help="Compare to llvm-exegesis output")
    docs_c_parser.add_argument("db_winic", help="Path to database YAML file")
    docs_c_parser.add_argument("db_exegesis", nargs="+", help="Paths to exegesis YAML files")
    docs_c_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    docs_c_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    # compare to osaca
    docs_c_parser = sub_compare_parser.add_parser("osaca", help="Compare to osaca database")
    docs_c_parser.add_argument("db_winic", help="Path to database YAML file")
    docs_c_parser.add_argument("db_osaca", help="Path to exegesis YAML file")
    docs_c_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to compare")
    docs_c_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    # plot command
    plot_parser = subparsers.add_parser("plot", help="Generate plots out of hardcoded data")
    plot_parser.add_argument("path", help="Output path")
    plot_parser.add_argument("--mode", choices=["TP", "LAT", "BOTH"], default="BOTH", help="Which values to plot")

    # stat command
    stat_parser = subparsers.add_parser("stat", help="Show statistics for a WINIC database")
    sub_stat_parser = stat_parser.add_subparsers(dest="stat_type")

    range_parser = sub_stat_parser.add_parser(
        "ranges", help="Count how many instructions have ranges instead of exact values"
    )
    range_parser.add_argument("db", help="Path to database YAML file")
    range_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print instruction names in addition to stats"
    )

    sublat_parser = sub_stat_parser.add_parser(
        "sublatencies", help="Count how many instructions have distinct sublatency values"
    )
    sublat_parser.add_argument("db", help="Path to database YAML file")
    sublat_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print instruction names in addition to stats"
    )

    plot_parser = sub_stat_parser.add_parser("distribution", help="Plot the distribution of TP/LAT values")
    plot_parser.add_argument("db", help="Path to database YAML file")

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
        case "diff":
            from analysis.comparison.db_diff import db_diff

            db_diff(args.db1, args.db2, args.mode, args.verbose)
        case "compare":
            if args.compare_source == "docs":
                if args.arch == "V2":
                    from analysis.comparison.compare_v2 import compare_winic_v2

                    compare_winic_v2(args.db, args.mode, args.verbose)
                elif args.arch == "ZEN4":
                    from analysis.comparison.compare_zen4_sheet import compare_winic_zen4_sheet

                    compare_winic_zen4_sheet(args.db, args.mode, args.verbose)
            elif args.compare_source == "exegesis":
                from analysis.comparison.compare_exegesis import compare_winic_exegesis

                if isinstance(args.db_exegesis, str):
                    args.db_exegesis = [args.exegesis]
                compare_winic_exegesis(args.db_winic, args.db_exegesis, args.mode, args.verbose)
            elif args.compare_source == "osaca":
                from analysis.comparison.compare_osaca import compare_winic_osaca

                compare_winic_osaca(args.db_winic, args.db_osaca, args.mode, args.verbose)
            elif args.compare_source == "uops":
                import analysis.globals as globals
                from analysis.comparison.compare_uops import compare_winic_uops

                globals.dbg_llvm_name = args.instruction
                compare_winic_uops(args.db, args.mode, args.arch, args.verbose)
                # plot(lat_res, tp_res, args.output, args.mode)
        case "plot":
            plot(None, None, args.path, args.mode)
        case "stat":
            if args.stat_type == "ranges":
                count_ranges(args.db, args.verbose)
            elif args.stat_type == "sublatencies":
                count_instr_different_sublatencies(args.db, args.verbose)
            elif args.stat_type == "distribution":
                plot_distribution(args.db)


if __name__ == "__main__":
    main()
