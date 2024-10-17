import os
import zipfile
import hashlib
import json
import yara
from io import BytesIO

from . import Log
from . import oh_common
from . import oh_hap


class oh_app(oh_common.oh_package):
    def __init__(self, value):
        Log.info(f"oh_app init {type(value)}")
        if (isinstance(value, str)):
            if (not value.endswith(".app")):
                raise oh_common.ParaNotValid("Not a valid app type, must .app")
        super().__init__(value)
        self.haps = dict()
        for fname in self.package.namelist():
            if fname.endswith(".hap"):
                zfiledata = BytesIO(self.package.read(fname))
                hap = oh_hap(zfiledata)
                self.haps[fname] = hap

    def extract_all_to(self, unzip_folder: str, unzip_sub_hap=True) -> bool:
        try:
            self.package.extractall(unzip_folder)
            if (unzip_sub_hap):
                for root, dirs, files in os.walk(unzip_folder):
                    for fname in files:
                        if (len(fname) > 4 and fname.endswith(".hap")):
                            Log.info(f"extract hap {fname} in {unzip_folder}")
                            oh_common.extract_local_zip_to(
                                os.path.join(unzip_folder, fname),
                                os.path.join(unzip_folder, f"hap_extract_{fname[: -4]}"))
            return True
        except zipfile.BadZipFile:
            Log.warn(f"{self.sha1} Bad ZIP file, {self.file_path}")
            return False

    def get_haps_name(self) -> list:
        return list(self.haps.keys())

    def get_haps_dict(self) -> dict:
        return self.haps

    def get_haps(self) -> list:
        return list(self.haps.values())

    def get_hap(self, name: set):
        if (name in self.haps.keys()):
            return self.haps[name]
        else:
            return None

    def is_certificated(self) -> bool:
        pass

    def filters_postfix_white_all_haps(self, rules: dict) -> dict:
        not_white_files_dict = dict()
        for fname, hap in self.haps.items():
            not_white_files_dict[fname] = hap.filters_postfix_white(rules)
        return not_white_files_dict

    def filters_postfix_black_all_haps(self, rules: dict) -> dict:
        not_black_files_dict = dict()
        for fname, hap in self.haps.items():
            not_black_files_dict[fname] = hap.filters_postfix_black(rules)
        return not_black_files_dict

    def filters_postfix_white_app_level(self, rules) -> list:
        # not filter files in haps, only scan app
        pass

    def filters_postfix_black_app_level(self, rules) -> list:
        # not filter files in haps, only scan app
        pass
