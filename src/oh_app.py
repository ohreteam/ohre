import zipfile
import hashlib
import json
import .Log as Log
import yara


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


class h_app(object):
    def __init__(self, path: str):
        Log.info(f"h_app init {path}")
        self.file_path = path
        self.app = zipfile.ZipFile(path, "r")
        self.files = self.app.namelist()
        self.app_md5 = cal_md5(path)
        self.app_sha1 = cal_sha1(path)
        self.pack_info = None
        self.get_pack_info()  # try to set self.pack_info

    def extract_all_to(self, unzip_folder: str):
        try:
            self.app.extractall(unzip_folder)
        except zipfile.BadZipFile:
            Log.warn(f"{self.app_md5} {self.app_sha1} Bad ZIP file, {self.file_path}")
            return False

    def get_files(self) -> list[str]:
        # return files's name
        return self.files

    def get_file(self, filename):
        try:
            return self.app.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def md5(self, filename="") -> str:
        if (filename == ""):
            return self.app_md5
        else:
            raise Exception("Not implemented")

    def sha1(self, filename="") -> str:
        if (filename == ""):
            return self.app_sha1
        else:
            raise Exception("Not implemented")

    def get_bundle_name(self) -> str:
        if (self.pack_info is not None and
            "summary" in self.pack_info.keys() and
                "app" in self.pack_info["summary"].keys()
                and "bundleName" in self.pack_info["summary"]["app"].keys()):
            return self.pack_info["summary"]["app"]["bundleName"]
        else:
            Log.warn(f"get bundle name failed")
            return ""

    def get_version(self):
        return self.pack_info["summary"]["app"]["version"]

    def get_version_name(self) -> str:
        return str(self.pack_info["summary"]["app"]["version"]["name"])

    def get_pack_info(self) -> dict:
        ret = {}
        for fname in self.files:
            if (fname.endswith("pack.info")):
                json_string = self.get_file(fname).decode("utf-8", errors="ignore")
                Log.info(f"{fname} {json_string}")
                json_data = json.loads(json_string)
                ret[fname] = json_data
        if (self.pack_info is None):
            if ("pack.info" in ret.keys()):
                self.pack_info = ret["pack.info"]
            else:
                Log.warn(f"pack.info not found")
        return ret

    def apply_yara_rule(
            self, rule_str: str = "", rule_path: str = "", file_post_fix: str = "", file_filter: str = "", file_list: list = []):
        all_files = file_list if (len(file_list)) else self.get_files()
        # === yara rule
        Log.info(f"apply_yara_rule: rule_str/rule_path len {len(rule_str)}/{len(rule_path)}")
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
        for fname in files_need:
            matches = rules.match(data=self.get_file(fname))
            if (len(matches)):
                print(f"matches: {matches}")
