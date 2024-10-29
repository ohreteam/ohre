import fnmatch
import hashlib
import io
import json
import os
import zipfile
from typing import Any, Dict, List

import yara

from ohre.misc import Log

HAP_EXTRACT_PREFIX = "hap_extract_"


class FileNotPresent(Exception):
    pass


class ParaNotValid(Exception):
    pass


def fname_in_pattern_list(fname, pattern_list: List) -> bool:
    for patt in pattern_list:
        if (fnmatch.fnmatch(fname, patt)):
            return True
    return False


def cal_md5(file_path) -> str:
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def cal_sha1(file_path) -> str:
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()


def extract_local_zip_to(zip_path: str, unzip_folder: str):
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(unzip_folder)
    except zipfile.BadZipFile:
        Log.warn(f"unzip {zip_path} to {unzip_folder}. Bad ZIP file")
        return False


class oh_package(object):
    def __init__(self, value):
        Log.debug(f"oh_package init {type(value)} {value}")
        self.file_path = ""
        self._md5 = None
        self._sha1 = None
        if (isinstance(value, str)):
            self.file_path = value
            self.package = zipfile.ZipFile(value, "r")
            self._md5 = cal_md5(value)
            self._sha1 = cal_sha1(value)
        elif (isinstance(value, zipfile.ZipFile)):
            self.package = value
        elif (isinstance(value, io.BytesIO)):
            self.package = zipfile.ZipFile(value, "r")
        else:
            Log.error(f"{self._sha1} ERROR! init oh_package failed, value type {type(value)} NOT supported")

        self.files = self.package.namelist()
        self.pack_info = None
        self.get_pack_info()

    @property
    def sha1(self):
        return self._sha1

    @property
    def md5(self):
        return self._md5

    def extract_all_to(self, unzip_folder: str):
        try:
            self.package.extractall(unzip_folder)
        except zipfile.BadZipFile:
            Log.warn(f"{self._sha1} Bad ZIP file, {self.file_path}")
            return False

    def get_files(self) -> list[str]:
        # return files's name
        return self.files

    def get_file(self, filename) -> bytes:
        try:
            return self.package.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_md5(self, filename="") -> str:
        if (filename == ""):
            return self._md5
        else:
            raise Exception("Not implemented")

    def get_sha1(self, filename="") -> str:
        if (filename == ""):
            return self._sha1
        else:
            raise Exception("Not implemented")

    def get_bundle_name(self) -> str:
        if (self.pack_info is not None and
            "summary" in self.pack_info.keys() and
                "app" in self.pack_info["summary"].keys() and
                "bundleName" in self.pack_info["summary"]["app"].keys()):
            return self.pack_info["summary"]["app"]["bundleName"]
        else:
            Log.warn(f"{self._sha1} get bundle name failed")
            return ""

    def get_version(self) -> Dict:
        return self.pack_info["summary"]["app"]["version"]

    def get_version_name(self) -> str:
        return str(self.pack_info["summary"]["app"]["version"]["name"])

    def get_version_code(self) -> str:
        return str(self.pack_info["summary"]["app"]["version"]["code"])

    def get_pack_info(self) -> Dict:
        if (self.pack_info is not None):
            return self.pack_info
        ret = None
        for fname in self.files:
            Log.debug(f"{self.sha1} get_pack_info fname {fname}")
            if (fname == "pack.info"):
                json_string = self.get_file(fname).decode(
                    "utf-8", errors="ignore")
                Log.info(f"pack.info: {fname} {json_string}", False)
                ret = json.loads(json_string)
                self.pack_info = ret
                return ret
        Log.warn(f"{self._sha1} pack.info not found")
        return None

    def apply_yara_rule(self, rule_str: str = "", rule_path: str = "", fname_pattern_list: List = [],
                        file_list: list = []) -> list:
        # rule_str rule_path: yara rule str ot yara rule file path, specify one of them
        # file_list: if len==0, use all files to match file name pattern in fname_pattern_list
        all_files = file_list if (len(file_list)) else self.get_files()
        Log.info(f"{self._sha1} apply_yara_rule: all files {len(all_files)} patt list {len(fname_pattern_list)}")
        # === yara rule
        Log.info(
            f"{self._sha1} apply_yara_rule: rule_str/rule_path len {len(rule_str)}/{len(rule_path)}", False)
        if (len(rule_str)):
            rules = yara.compile(source=rule_str)
        elif (len(rule_path)):
            rules = yara.compile(filepath=rule_path)
        else:
            raise ParaNotValid(f"{self._sha1} both rule_str and rule_path are empty")
        # === filter
        files_need = []
        if (len(fname_pattern_list)):
            for fname in all_files:
                if (fname_in_pattern_list(fname, fname_pattern_list)):
                    files_need.append(fname)
        # === apply rule, scan start
        match_list = list()
        for fname in files_need:
            matches = rules.match(data=self.get_file(fname))
            if (len(matches)):
                Log.debug(f"{self._sha1} matches: {matches}")
                match_list.append(matches)
        return match_list
