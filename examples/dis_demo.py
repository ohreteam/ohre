import argparse
import cProfile
import datetime
import os
import pickle
import subprocess
import time

import ohre
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.PandaReverser import PandaReverser
from ohre.core import oh_app, oh_hap
from ohre.misc import Log, utils


def save_object(obj, filename):
    with open(filename, "wb") as file:
        pickle.dump(obj, file)


def load_object(filename):
    with open(filename, "rb") as file:
        obj = pickle.load(file)
    return obj


TMP_HAP_EXTRACT = "tmp_hap_extract"
TMP_APP_EXTRACT = "tmp_app_extract"
ARK_DISASM = "path2ark_disasm"

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/dis_demo.py name.abc.dis
    start_time = time.time()
    Log.init_log("abcre", ".")
    ohre.set_log_level("info")
    ohre.set_log_print(True)
    Log.info(f"START {__file__}", True)
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

    save_object(panda_re, "temp.pkl")
    panda_re: PandaReverser = load_object("temp.pkl")

    Log.info(f"> panda_re: {panda_re}")

    # for addr, lit in panda_re.dis_file.literals.items():
    #     print(f">> {lit._debug_vstr()}")
    # for module_name, name_meth_d in panda_re.dis_file.methods.items():
    #     for methd_name, meth in name_meth_d.items():
    #         print(f">> {meth._debug_vstr()}")
    # for module_name, record in panda_re.dis_file.records.items():
    #     print(f">> {record._debug_vstr()}")
    # for asmstr in panda_re.dis_file.asmstrs:
    #     print(f">> {asmstr}")

    # === reverse truly START # strip & method full name and set it to below line
    # module_method_name: str = "vulwebview.src.main.ets.pages.Index.func_main_0"
    # module_name, method_name = utils.split_to_module_method_name(module_method_name)
    # print(f">> before CF {panda_re.dis_file.methods[module_name][method_name]._debug_vstr()}")
    # panda_re.split_native_code_block(module_name, method_name)
    # print(f">> CF built {panda_re.dis_file.methods[module_name][method_name]._debug_vstr()}")
    # panda_re.trans_NAC_to_TAC(module_name, method_name)
    # print(f">> TAC built {panda_re.dis_file.methods[module_name][method_name]._debug_vstr()}")
    # # panda_re._code_lifting_algorithms(module_name, method_name)
    # cProfile.run("panda_re._code_lifting_algorithms(module_name, method_name)")
    # print(f">> after lifting {panda_re.dis_file.methods[module_name][method_name]._debug_vstr()}")

    nac_total = panda_re.get_insts_total()
    panda_re.trans_lift_all_method()
    i, total = 0, panda_re.method_len()
    for module_name, name_meth_d in panda_re.dis_file.methods.items():
        for method_name, meth in name_meth_d.items():
            print(f">> [{i}/{total}]after lift {panda_re.get_meth(module_name, method_name)._debug_vstr()}\n")
            i += 1

    tac_total = panda_re._get_tac_total()
    todo_tac, tac_opstr_set = panda_re.get_tac_unknown_count()
    final_tac_total = panda_re.get_insts_total()
    print(f"todo_tac {todo_tac}/{tac_total} {todo_tac / tac_total:.4f} /nac /{nac_total} {todo_tac / nac_total:.4f}")
    print(f"lifting_algorithms {final_tac_total}/{tac_total} {final_tac_total / tac_total:.4f}")
    print(f"tac_opstr_set {len(tac_opstr_set)} {tac_opstr_set}")

    panda_re._module_analysis_algorithms()
    print(f"\n\n panda_re.dis_file.module_info {len(panda_re.dis_file.module_info)} {panda_re}")
    for module_name, module_info in panda_re.dis_file.module_info.items():
        print(f"> {module_info._debug_vstr()}")
    print("\n\n")

    print(f"panda_re.dis_name {panda_re.dis_name} output write to test.out")
    file = open(f"test.out", "w")
    content = panda_re.dis_name + " time: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n"
    i, total = 0, panda_re.method_len()
    for module_name, name_meth_d in panda_re.dis_file.methods.items():
        for method_name, meth in name_meth_d.items():
            content += f">> [{i}/{total}]after lift \n{panda_re.get_meth(module_name, method_name)._debug_vstr()}\n\n"
            i += 1
    content += f"\n\n panda_re.dis_file.module_info {len(panda_re.dis_file.module_info)}\n\n"
    for module_name, module_info in panda_re.dis_file.module_info.items():
        content += f"{module_info._debug_vstr()}\n"
    content += f"lifting_algorithms {final_tac_total}/{tac_total} {final_tac_total / tac_total:.4f}\n"
    content += f"tac_opstr_set {len(tac_opstr_set)} {tac_opstr_set}\n"
    file.write(content)
    file.close()

    total_time = time.time() - start_time
    Log.info(f"END {__file__} {total_time / 60:.4f} min used", True)
