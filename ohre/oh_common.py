import io
import os
import zipfile
import hashlib
import json
import tempfile
import yara

from . import Log
from typing import Any, Dict


class FileNotPresent(Exception):
    pass


class ParaNotValid(Exception):
    pass


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
        Log.info(f"oh_package init {type(value)} {value}")
        self.file_path = ""
        self.md5 = None
        self.sha1 = None
        if (isinstance(value, str)):
            self.file_path = value
            self.package = zipfile.ZipFile(value, "r")
            self.md5 = cal_md5(value)
            self.sha1 = cal_sha1(value)
        elif (isinstance(value, zipfile.ZipFile)):
            self.package = value
        elif (isinstance(value, io.BytesIO)):
            self.package = zipfile.ZipFile(value, "r")
        else:
            Log.error(f"ERROR! init oh_package failed, value type {type(value)} NOT supported")

        self.files = self.package.namelist()
        self.pack_info = None
        self.get_pack_info()

    def extract_all_to(self, unzip_folder: str):
        try:
            self.package.extractall(unzip_folder)
        except zipfile.BadZipFile:
            Log.warn(f"{self.sha1} Bad ZIP file, {self.file_path}")
            return False

    def get_files(self) -> list[str]:
        # return files's name
        return self.files

    def get_file(self, filename):
        try:
            return self.package.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_md5(self, filename="") -> str:
        if (filename == ""):
            return self.md5
        else:
            raise Exception("Not implemented")

    def get_sha1(self, filename="") -> str:
        if (filename == ""):
            return self.sha1
        else:
            raise Exception("Not implemented")

    def get_bundle_name(self) -> str:
        if (self.pack_info is not None and
            "summary" in self.pack_info.keys() and
                "app" in self.pack_info["summary"].keys() and
                "bundleName" in self.pack_info["summary"]["app"].keys()):
            return self.pack_info["summary"]["app"]["bundleName"]
        else:
            Log.warn(f"get bundle name failed")
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
            Log.debug(f"get_pack_info fname {fname}")
            if (fname == "pack.info"):
                json_string = self.get_file(fname).decode(
                    "utf-8", errors="ignore")
                Log.info(f"pack.info: {fname} {json_string}", False)
                ret = json.loads(json_string)
                self.pack_info = ret
                return ret
        Log.warn(f"pack.info not found")
        return None

    def apply_yara_rule(self, rule_str: str = "", rule_path: str = "", file_post_fix: str = "", file_filter: str = "",
                        file_list: list = []) -> list:
        # rule_str rule_path: yara rule str ot yara rule file path, specify one of them
        all_files = file_list if (len(file_list)) else self.get_files()
        Log.info(f"apply_yara_rule all files cnt {len(all_files)}")
        # === yara rule
        Log.info(
            f"apply_yara_rule: rule_str/rule_path len {len(rule_str)}/{len(rule_path)}", False)
        if (len(rule_str)):
            rules = yara.compile(source=rule_str)
        elif (len(rule_path)):
            rules = yara.compile(filepath=rule_path)
        else:
            raise ParaNotValid("both rule_str and rule_path are empty")
        # === filter
        files_need = []
        for fname in all_files:
            need_flag = True
            if (len(file_post_fix) and (not fname.endswith(file_post_fix))):
                need_flag = False
            if (len(file_filter) and (not file_filter in fname)):
                need_flag = False
            if (need_flag):
                files_need.append(fname)
        # === apply rule, scan start
        match_list = list()
        for fname in files_need:
            matches = rules.match(data=self.get_file(fname))
            if (len(matches)):
                print(f"matches: {matches}")
                match_list.append(matches)
        return match_list
