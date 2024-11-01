import copy
import json
import os
import zipfile
from io import BytesIO
from typing import Any, Dict, List

from ohre.core import oh_common, oh_hap
from ohre.misc import Log


class oh_app(oh_common.oh_package):
    def __init__(self, value):
        Log.debug(f"oh_app init {type(value)}")
        if (isinstance(value, str)):
            if (not value.endswith(".app")):
                raise oh_common.ParaNotValid("Not a valid app type, must .app")
        super().__init__(value)
        self.haps = dict()
        for fname in self.package.namelist():
            if (len(fname) > 4 and fname.endswith(".hap")):
                zfiledata = BytesIO(self.package.read(fname))
                hap = oh_hap.oh_hap(zfiledata)
                self.haps[fname] = hap

        self.haps_files_path = dict()
        for hap_name, hap in self.get_haps_dict().items():
            self.haps_files_path[hap_name] = list()
            for fpath in hap.get_files():
                self.haps_files_path[hap_name].append(fpath)

    def get_files_in_app(self) -> List[str]:
        # return files's name only in app
        return self.files

    def get_files_in_haps(self) -> Dict[str, List]:
        # return files's name in all haps
        return self.haps_files_path

    def get_files(self) -> List[str]:
        # return files's name in app and all haps
        ret = copy.deepcopy(self.files)
        for hap_name, f_list in self.haps_files_path.items():
            ret.extend([os.path.join(hap_name, f_path) for f_path in f_list])
        return ret

    def get_file(self, filename: str) -> bytes:
        dir_name = os.path.dirname(filename)
        if (not dir_name):
            return super().get_file(filename)
        while (os.path.dirname(dir_name)):
            dir_name = os.path.dirname(dir_name)
        f_path = filename[len(dir_name)+1:]
        Log.debug(f"app get_file in hap {dir_name} {f_path}")
        if (dir_name in self.get_haps_name()):
            return self.haps[dir_name].get_file(f_path)

    def extract_all_to(self, unzip_folder: str, unzip_sub_hap=True) -> bool:
        try:
            self.package.extractall(unzip_folder)
            if (unzip_sub_hap):
                for root, dirs, files in os.walk(unzip_folder):
                    for fname in files:
                        if (len(fname) > 4 and fname.endswith(".hap")):
                            Log.info(f"{self.sha1} extract hap {fname} to {unzip_folder}")
                            oh_common.extract_local_zip_to(
                                os.path.join(unzip_folder, fname),
                                os.path.join(unzip_folder, f"{oh_common.HAP_EXTRACT_PREFIX}{fname[: -4]}"))
            return True
        except zipfile.BadZipFile:
            Log.warn(f"{self.sha1} Bad ZIP file, {self.file_path}")
            return False

    def get_haps_name(self) -> List[str]:
        return list(self.haps.keys())

    def get_haps_dict(self) -> Dict[str, oh_hap.oh_hap]:
        return self.haps

    def get_haps(self) -> List[oh_hap.oh_hap]:
        return list(self.haps.values())

    def get_hap(self, name: str) -> oh_hap.oh_hap:
        if (name in self.haps.keys()):
            return self.haps[name]
        else:
            return None

    def is_certificated(self) -> bool:
        pass

    def filters_filename_white_all_haps(self, rules: Dict) -> Dict:
        not_white_files_dict = dict()
        Log.info(f"{self.sha1} all haps filter white: {rules}")
        for fname, hap in self.haps.items():
            not_white_files_dict[fname] = hap.filters_filename_white(rules)
        return not_white_files_dict

    def filters_filename_black_all_haps(self, rules: Dict) -> Dict:
        not_black_files_dict = dict()
        Log.info(f"{self.sha1} all haps filter black: {rules}")
        for fname, hap in self.haps.items():
            not_black_files_dict[fname] = hap.filters_filename_black(rules)
        return not_black_files_dict

    def filters_filename_white_app_level(self, rules: Dict) -> List:
        # not filter files in haps, only scan app
        not_white_files = list()
        Log.info(f"{self.sha1} app level filter white: {rules}")
        if ("." in rules.keys()):
            pattern_list = rules["."]
            for fpath in self.files:
                if (os.sep not in fpath):  # only level-1 files
                    Log.debug(f"app level filter white: analyzing {fpath}")
                    if (not oh_common.fname_in_pattern_list(fpath, pattern_list)):
                        not_white_files.append(fpath)
        return sorted(list(set(not_white_files)))

    def filters_filename_black_app_level(self, rules: Dict) -> List:
        # not filter files in haps, only scan app
        pass
