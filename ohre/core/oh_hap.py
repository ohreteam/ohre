import fnmatch
import hashlib
import json
import os
import zipfile
from typing import Any, Dict, List

import yara

from ohre.core import oh_common
from ohre.misc import Log
from ohre.res_analyzer.oh_resbuf import ResIndexBuf


class oh_hap(oh_common.oh_package):
    def __init__(self, value):
        Log.debug(f"oh_hap init {type(value)}")
        if (isinstance(value, str)):
            if (not value.endswith(".hap")):
                raise oh_common.ParaNotValid("Not a valid hap type, must be .hap")
        super().__init__(value)
        self.res_index = None

    def filter_filename_white(self, path: str, pattern_list: List) -> List:
        # path: a path prefix to specify the dir to be scanned
        # "*": all files include sub path and root path of this hap
        # pattern_list: file name pattern that are allowed in the corressponding path
        not_white_files = []
        for fpath in self.files:
            if (fpath.startswith(path) or path == "*"):
                Log.debug(f"{self.sha1} filter white in {path}: fpath patt {fpath} {pattern_list}")
                if (not oh_common.fname_in_pattern_list(os.path.basename(fpath), pattern_list)):
                    not_white_files.append(fpath)
        return sorted(not_white_files)

    def filters_filename_white(self, rules: Dict) -> List:
        # ".": level 1 files(NOT in a sub folder)
        # here, a filter means a k,v in rules dict. k: path, v: white filename pattern list
        # NOTE: As long as 1 whitelist rule hit, the file will be considered as non-whitelisted.
        # e.g. rules is {"*": ["*.png"], ".": ["pack.json"]}. then pack.json is a non-whitelisted file here
        not_white_files = []
        for path, pattern_list in rules.items():
            if (path == "."):
                continue
            l = self.filter_filename_white(path, pattern_list)
            not_white_files.extend(l)
        if ("." in rules.keys()):
            pattern_list = rules["."]
            for fpath in self.files:
                if (os.sep not in fpath):
                    Log.debug(f"{self.sha1} filter white in . : fpath patt {fpath} {pattern_list}")
                    if (not oh_common.fname_in_pattern_list(fpath, pattern_list)):
                        not_white_files.append(fpath)
        return sorted(list(set(not_white_files)))

    def filter_filename_black(self, path: str, pattern_list: List) -> List:
        black_files = []
        for fpath in self.files:
            if (fpath.startswith(path) or path == "*"):
                for patt in pattern_list:
                    Log.debug(f"{self.sha1} filter black in {path}: fpath patt {fpath} {patt}")
                    if (fnmatch.fnmatch(os.path.basename(fpath), patt)):
                        black_files.append(fpath)
        return sorted(black_files)

    def filters_filename_black(self, rules: Dict) -> List:
        black_files = []
        for path, pattern_list in rules.items():
            if (path == "."):
                continue
            l = self.filter_filename_black(path, pattern_list)
            black_files.extend(l)
        if ("." in rules.keys()):
            pattern_list = rules["."]
            for fpath in self.files:
                if (os.sep not in fpath):
                    for patt in pattern_list:
                        Log.debug(f"{self.sha1} filter black in . : fpath patt {fpath} {patt}")
                        if (fnmatch.fnmatch(fpath, patt)):
                            black_files.append(fpath)
        return sorted(list(set(black_files)))

    def get_resources_index_raw(self) -> bytes:
        if ("resources.index" not in self.files):
            Log.error(f"{self.sha1} resources.index NOT found in this hap")
            return bytes()
        else:
            return super().get_file("resources.index")

    def get_resources_index(self) -> Dict:
        if (self.res_index is None):
            buf = self.get_resources_index_raw()
            res_content = ResIndexBuf(buf)
            self.res_index = res_content.resources_content
        return self.res_index

    def compare_files_with_resources_index(self) -> Dict:
        if (self.res_index is None):
            self.get_resources_index()

        self.get_module_json()  # TODO: This might not exist if not called

        # TODO: Verify if the prefix is correct
        files_prefix = "resources"
        resources_prefix = os.path.join(self.get_module_package_name(), "resources")

        # TODO: We need a better way to pre-filter, e.g., using "file_type"
        res_index_list = [res["file_value"] for res in self.res_index["resource_items"].values()]

        def filter_path(prefix, path_list):
            import pathlib
            return [
                path.relative_to(prefix).as_posix()
                for p in path_list if (path := pathlib.Path(p)).is_relative_to(prefix)
            ]

        res_list = filter_path(resources_prefix, res_index_list)
        files_list = filter_path(files_prefix, self.files)

        return {"files_only": list(set(files_list) - set(res_list)),
                "resource_index_only": list(set(res_list) - set(files_list)),
                "intersection ": list(set(res_list) & set(files_list))}

    # === module.json analysis START ===

    def get_module_json_raw(self) -> bytes:
        if ("module.json" not in self.files):
            Log.error(f"{self.sha1} module.json NOT found in this hap")
            return bytes()
        else:
            return super().get_file("module.json")

    def get_module_json(self) -> Dict:
        if ("module.json" not in self.files):
            Log.error(f"{self.sha1} module.json NOT found in this hap")
            return dict()
        json_string = self.get_file("module.json").decode("utf-8", errors="ignore")
        self.module_json_dict = json.loads(json_string)
        return self.module_json_dict

    def get_module_name(self) -> str:
        if ("module" in self.module_json_dict and "name" in self.module_json_dict["module"]):
            return self.module_json_dict["module"]["name"]
        return ""

    def get_module_package_name(self) -> str:
        if ("module" in self.module_json_dict and "packageName" in self.module_json_dict["module"]):
            return self.module_json_dict["module"]["packageName"]
        return ""

    def get_module_device_types(self) -> List:
        if ("module" in self.module_json_dict and "deviceTypes" in self.module_json_dict["module"]):
            return self.module_json_dict["module"]["deviceTypes"]
        return ""
    # === module.json analysis END ===
