import argparse
import datetime
import os
import subprocess

import ohre
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.PandaReverser import PandaReverser
from ohre.core import oh_app, oh_hap
from ohre.misc import Log

TMP_HAP_EXTRACT = "tmp_hap_extract"
TMP_APP_EXTRACT = "tmp_app_extract"
ARK_DISASM = "path2ark_disasm"

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/dis_demo.py name.abc.dis
    Log.init_log("abcre", ".")
    ohre.set_log_level("info")
    ohre.set_log_print(True)
    Log.info(f"START {__file__}")
    parser = argparse.ArgumentParser()
    parser.add_argument("in_path", type=str, help="path to the dis file (ark_disasm-ed abc) or hap/app")
    arg = parser.parse_args()
    in_path = arg.in_path
    if (in_path.endswith(".dis")):
        dis_file: DisFile = DisFile(in_path)
    elif (in_path.endswith(".hap")):
        hhap = oh_hap.oh_hap(in_path)
        hhap.extract_all_to(TMP_HAP_EXTRACT)
        abc_file = os.path.join(TMP_HAP_EXTRACT, "ets", "modules.abc")
        dis_file = f"{os.path.splitext(os.path.basename(in_path))[0]}.abc.dis"  # os.path.splitext(file_name)[0]
        result = subprocess.run([ARK_DISASM, abc_file, dis_file], capture_output=True, text=True)
        dis_file: DisFile = DisFile(dis_file)
    panda_re: PandaReverser = PandaReverser(dis_file)
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
    FUNC_IDX = 12  # 5: onWindowStageCreate, call loadContent and pass a mothod as para; 7: mothod that used as para
    # print(f">> before CF {dis_file.methods[FUNC_IDX]._debug_vstr()}")
    panda_re.split_native_code_block(FUNC_IDX)
    # print(f">> CF built {panda_re.dis_file.methods[FUNC_IDX]._debug_vstr()}")
    panda_re.trans_NAC_to_TAC(method_id=FUNC_IDX)
    print(f">> TAC built {panda_re.dis_file.methods[FUNC_IDX]._debug_vstr()}")
    panda_re._code_lifting_algorithms(FUNC_IDX)
    print(f">> after lifting {panda_re.dis_file.methods[FUNC_IDX]._debug_vstr()}")

    # nac_total = panda_re.get_insts_total()
    # for idx in range(panda_re.method_len()):
    #     panda_re.split_native_code_block(idx)
    #     print(f">> [{idx}/{panda_re.method_len()}] CF built {panda_re.dis_file.methods[idx]}")
    #     panda_re.trans_NAC_to_TAC(method_id=idx)
    # tac_total = panda_re.get_insts_total()
    # for idx in range(panda_re.method_len()):
    #     panda_re._code_lifting_algorithms(method_id=idx)
    #     print(f">> [{idx}/{panda_re.method_len()}] after lift {panda_re.dis_file.methods[idx]._debug_vstr()}")
    # todo_tac = panda_re.get_tac_unknown_count()
    # final_tac_total = panda_re.get_insts_total()
    # print(f"todo_tac {todo_tac}/{tac_total} {todo_tac/tac_total:.4f} /nac /{nac_total} {todo_tac/nac_total:.4f}")
    # print(f"lifting_algorithms {final_tac_total}/{tac_total} {final_tac_total/tac_total:.4f}")

    panda_re._module_analysis_algorithms()
    print(f"\n\n panda_re.dis_file.modulevar_d {panda_re.dis_file.modulevar_d}")

    print(f"panda_re.dis_name {panda_re.dis_name} output write to {panda_re.dis_name}.out")
    file = open(f"{panda_re.dis_name}.out", "w")
    content = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n"
    for idx in range(panda_re.method_len()):
        content += f">> [{idx}/{panda_re.method_len()}] after lift \n{panda_re.dis_file.methods[idx]._debug_vstr()}\n\n"
    file.write(content)
    file.close()
