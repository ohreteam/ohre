import argparse

import ohre
from ohre.abcre.dis.DisFile import DisFile
from ohre.misc import Log

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/dis_demo.py name.abc.dis
    Log.init_log("abcre", ".")
    ohre.set_log_level("info")
    ohre.set_log_print(True)
    parser = argparse.ArgumentParser()
    parser.add_argument("dis_path", type=str, help="path to the dis file (ark_disasm-ed abc)")
    arg = parser.parse_args()
    dis_path = arg.dis_path
    dis_file = DisFile(dis_path)

    print(f"> {dis_file}")
    # print(f"\n> {dis_file.debug_deep()}")
    for method in dis_file.methods:
        print(f">> {method.debug_short()}")
    for asmstr in dis_file.asmstrs:
        print(f">> {asmstr}")
