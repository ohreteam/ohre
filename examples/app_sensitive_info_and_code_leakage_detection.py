import sys

import ohre
import ohre.rules.filters_filename as filters_filename
from ohre.core import oh_app

# ohre.set_log_level("debug")
if (len(sys.argv) < 2):
    print("usage: python this_example.py app_path.app")
    sys.exit(0)
app_path = sys.argv[1]
happ = oh_app.oh_app(app_path)

print("extract:", happ.extract_all_to("tmp"))

# === senstive info detection: whether there is IP leakage
# NOTE: Because some version numbers are very similar to IP, there will be false positives
# passing yara rules with xx.yar path
print("hit:", happ.apply_yara_rule(rule_path="../ohre/rules/IP.yar"))
# passing yara rules with yara rule str
# print("hit:", happ.apply_yara_rule(rule_str="xxx"))
# scan json files only
print("hit:", happ.apply_yara_rule(rule_path="../ohre/rules/IP.yar", fname_pattern_list=["*.json"]))

# === code leakage detection: whether there is code files leakage
print("OHRE_HAP_BLACK", happ.filters_filename_black_all_haps(filters_filename.OHRE_HAP_BLACK))
print("detect proto files leakage", happ.filters_filename_black_all_haps({"*": ["*.proto"]}))
print("detect proto and c++ leakage", happ.filters_filename_black_all_haps({"*": ["*.proto", "*.cpp", "*.c++"]}))
print("detect json leakage in resources/base/media/",
      happ.filters_filename_black_all_haps({"resources/base/media/": ["*.json"]}))
print("detect invalid files in hap root",
      happ.filters_filename_white_all_haps(filters_filename.OHRE_HAP_ROOT_WHITE))
print("detect invalid files in app root",
      happ.filters_filename_white_app_level(filters_filename.OHRE_APP_WHITE))
