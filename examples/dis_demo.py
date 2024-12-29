import argparse

import ohre
from ohre.abcre.dis.ControlFlow import ControlFlow
from ohre.abcre.dis.PandaReverser import PandaReverser
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
    dis_file: DisFile = DisFile(dis_path)
    panda_re = PandaReverser(dis_file)
    print(f"> panda_re: {panda_re}")

    for lit in dis_file.literals:
        print(f">> {lit._debug_vstr()}")
    for method in dis_file.methods:
        print(f">> {method}")
    for record in dis_file.records:
        print(f">> {record._debug_vstr()}")
    for asmstr in dis_file.asmstrs:
        print(f">> {asmstr}")

    # === reverse truly START
    FUNC_IDX = 16
    # print(f">> before ControlFlow build {dis_file.methods[FUNC_IDX]._debug_vstr()}")
    panda_re.split_native_code_block(FUNC_IDX)
    print(f">> after ControlFlow build {panda_re.dis_file.methods[FUNC_IDX]._debug_vstr()}")
    panda_re.trans_NAC_to_TAC(method_id=FUNC_IDX)
