import fnmatch
import hashlib
import json
import os
import zipfile
from typing import Any, Dict, List

import yara

from ohre.core import oh_common
from ohre.misc import Log


class oh_hap(oh_common.oh_package):
    def __init__(self, value):
        Log.debug(f"oh_hap init {type(value)}")
        if (isinstance(value, str)):
            if (not value.endswith(".hap")):
                raise oh_common.ParaNotValid("Not a valid hap type, must be .hap")
        super().__init__(value)

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

    def get_resource_indx(self) -> bytes:
        if ("resources.index" not in self.files):
            Log.error(f"{self.sha1} resources.index NOT found in this hap")
            return bytes()
        else:
            return super().get_file("resources.index")
