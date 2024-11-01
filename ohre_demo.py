import argparse
import json
import os
import shutil
import sys
import time

import yara

import ohre
import ohre.rules.filters_filename as filters_filename
from ohre.core import oh_app, oh_hap

TMP_HAP_EXTRACT = "tmp_hap_extract"
TMP_APP_EXTRACT = "tmp_app_extract"


def test_oh_hap(app_path):
    hhap = oh_hap.oh_hap(app_path)
    hhap.extract_all_to(TMP_HAP_EXTRACT)
    print(f"{hhap.get_md5()} {hhap.get_sha1()} get_files() {hhap.get_files()}")
    print(f"{hhap.get_bundle_name()} get_version {hhap.get_version()} "
          f"version name/code {hhap.get_version_name()} {hhap.get_version_code()}")
    print(f"pack.info {hhap.get_pack_info()} {type(hhap.get_pack_info())}")

    ret = hhap.filters_filename_white({"resources/base/": ["*.png"]})
    print(f"filters_filename_white {ret}")
    hhap.apply_yara_rule(rule_path="ohre/rules/IP.yar")

    res_index = hhap.get_resources_index()
    print("Resources.index :\n", res_index)


def test_oh_app(app_path):
    happ = oh_app.oh_app(app_path)
    happ.extract_all_to(TMP_APP_EXTRACT)
    print(f"md5 {happ.md5} sha1 {happ.sha1} files in app {happ.get_files_in_app()}")
    print(f"get_files_in_haps {happ.get_files_in_haps()}")
    print(f"get_files {len(happ.get_files())} {happ.get_files()}")
    # print(f"get_file {happ.get_file('entry-default.hap/resources.index')}")
    # print(f"get_file {happ.get_file('entry-default.hap/resources/base/profile/backup_config.json')}")
    print(happ.get_haps_dict())
    for hap_name, hap in happ.get_haps_dict().items():
        print(f"{hap_name} hap sha1 {hap.sha1} files {len(hap.get_files())} {hap.get_files()}")
        print(f"hap module.json {hap.get_module_json_raw()} ")
        print(f"{type(hap.get_module_json())} {hap.get_module_json()}")
        print(f"{hap.get_module_name()} {hap.get_module_package_name()} {hap.get_module_device_types()}")
        d = hap.get_module_json()
        for k, v in d.items():
            print(f"k {k} v: {v}")

    print(f"{happ.get_bundle_name()} get_version {happ.get_version()} "
          f"version name/code {happ.get_version_name()} {happ.get_version_code()}")
    print(f"pack.info {happ.get_pack_info()} {type(happ.get_pack_info())}")

    ret = happ.filters_filename_white_all_haps({"*": ["*.png", "*.gif", "*.so"], ".": ["pack.info"]})
    print(f"filters_filename_white_all_haps {ret}")
    ret = happ.filters_filename_white_all_haps(filters_filename.OHRE_HAP_ROOT_WHITE)
    print(f"OHRE_HAP_ROOT_WHITE {ret}")
    ret = happ.filters_filename_black_all_haps(filters_filename.OHRE_HAP_BLACK)
    print(f"OHRE_HAP_BLACK {ret}")
    ret = happ.filters_filename_white_app_level(filters_filename.OHRE_APP_WHITE)
    print(f"OHRE_APP_WHITE {ret}")

    happ.apply_yara_rule(rule_path="ohre/rules/IP.yar")
    print(f"is release: {happ.is_api_version_release()} get_packages_device_type {happ.get_packages_device_type()}")
    print(f"api target {happ.get_taget_api_version()} compatible {happ.get_compatible_api_version()}")


def test_oh_hap_resource_anaylsis(hap_path):
    hhap = oh_hap.oh_hap(hap_path)
    hhap.extract_all_to(TMP_HAP_EXTRACT)
    print(json.dumps(hhap.compare_files_with_resources_index(), indent=4))

    print("============== \"only path\" test, please ignore this =====================")
    hhap.files.append("resources/files_only_test")
    print(json.dumps(hhap.compare_files_with_resources_index(), indent=4))

    hhap.res_index["resource_items"]["resources_index_only_test"] = (
        {
            "file_size": 4096,
            "file_type": "resources_index_only_test",
            "file_value": f"{hhap.get_module_package_name()}/resources/resources_index_only_test",
            "file_name": "resources_index_only_test"
        })
    print(json.dumps(hhap.compare_files_with_resources_index(), indent=4))
    print("===========================================================================")


if __name__ == "__main__":  # clear; pip install -e .; python3 ohre_demo.py native_tmpl.hap
    parser = argparse.ArgumentParser()
    parser.add_argument("app_path", type=str, help="TBD")
    parser.add_argument("--resource_analysis", action="store_true", help="TBD")
    arg = parser.parse_args()

    start_time = time.time()
    app_path = arg.app_path
    print(f"[demo] START: {app_path}")
    ohre.set_log_dir(".")  # put log file to pwd (current path)
    ohre.set_log_level("debug")  # if bugs occured, set to debug level and attach xxx.log at issue
    ohre.set_log_level("info")
    ohre.set_log_print(True)  # set true to print log at console too
    if (os.path.exists(TMP_APP_EXTRACT)):
        shutil.rmtree(TMP_APP_EXTRACT)
    if (os.path.exists(TMP_HAP_EXTRACT)):
        shutil.rmtree(TMP_HAP_EXTRACT)

    if (app_path.endswith(".hap")):
        if (arg.resource_analysis):
            test_oh_hap_resource_anaylsis(app_path)
        else:
            test_oh_hap(app_path)
    else:
        test_oh_app(app_path)
    total_time = time.time() - start_time
    print(f"[demo] END, {total_time / 60:.4f} min used")
