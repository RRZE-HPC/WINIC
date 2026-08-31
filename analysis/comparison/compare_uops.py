from analysis.globals import *
from analysis.parsing.parse_winic import read_WINIC_db
from analysis.comparison.helper import compare_lists
from typing import Literal
import os


def compare_winic_uops(database, mode: Literal["LAT", "TP", "BOTH"], march: str, verbose: bool = False) -> Counters:

    # parse measured instructions
    from analysis.parsing.parse_winic import parse_WINIC_instruction
    from analysis.parsing.parse_uops import parse_uops_database

    db = read_WINIC_db(database)
    uops_instructions = parse_uops_database(march)
    w_instructions = [parse_WINIC_instruction(db_entry, "X86") for db_entry in db]
    w_instructions = [x for x in w_instructions if x is not None]
    return compare_lists(w_instructions, uops_instructions, mode, "loose", verbose)
