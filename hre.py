import os
import sys
import time
import yara
import zipfile
from ohre import oh_app
from ohre import oh_hap

TMP_HAP_EXTRACT = "tmp_hap_extract"


def yara_local_test():
    rules = yara.compile(filepath="rules/wxid.yar")
    data = '''
    {
        "wx0123456789abcdef"
        "some other text"
    }
    '''

    matches = rules.match(data=data)
    print(f"matches {matches}")
    for match in matches:
        print(f"Rule: {match.rule} {type(match)} {match.tags} {match.meta} {match.strings}")


def test_oh_hap(app_path):
    hhap = oh_hap(app_path)
    hhap.extract_all_to(TMP_HAP_EXTRACT)
    print(f"{hhap.get_md5()} {hhap.get_sha1()} hhap.get_files() {hhap.get_files()} ")
    print(f"{hhap.get_bundle_name()} get_version {hhap.get_version()} version name/code {hhap.get_version_name()} {hhap.get_version_code()}")
    print(f"get_pack_info {hhap.get_pack_info()} {type(hhap.get_pack_info())}")


if __name__ == "__main__":  # clear; pip install -e .; python3 hre.py native_tmpl.hap
    start_time = time.time()
    if (len(sys.argv) < 2):
        print("python hre.py app_path")
        sys.exit(0)
    app_path = sys.argv[1]
    print(f"[hre] START: {app_path}")
    # ha = oh_app(app_path)
    # os.system("rm -rf tmp_extract")
    # ha.extract_all_to("tmp_extract")
    # print(ha.get_files())
    # for fname in ha.get_files():
    #     print(f"{fname} : {len(ha.get_file(fname))}")
    # print(ha.get_pack_info())
    # print(f"ha.get_bundle_name() {type(ha.get_bundle_name())} {ha.get_bundle_name()}")
    # print(f"ha.get_version() {ha.get_version()}")
    # print(f"ha.get_version_name() {ha.get_version_name()}")

    # ha.apply_yara_rule(rule_path="rules/wxid.yar")
    test_oh_hap(app_path)
    total_time = time.time() - start_time
    print(f"[hre] END, {total_time/60:.4f} min used")
