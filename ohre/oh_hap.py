import os
import zipfile
import hashlib
import json
import yara

from . import Log
from . import oh_common


class oh_hap(oh_common.oh_package):
    def __init__(self, value):
        Log.info(f"oh_hap init {type(value)}")
        if (isinstance(value, str)):
            if (not value.endswith(".hap")):
                raise oh_common.ParaNotValid("Not a valid hap type, must .hap")
        super().__init__(value)

    def filter_postfix_white(self, path: str, file_post_fix_list) -> list:
        # path: a path prefix to specify the dir to be scanned
        # file_post_fix_list: postfix that are allowed in the path
        not_white_files = []
        for fname in self.files:
            if (fname.startswith(path)):
                IS_WHILE = False
                for post_fix in file_post_fix_list:
                    if (fname.endswith(post_fix)):
                        IS_WHILE = True
                if (IS_WHILE == False):
                    not_white_files.append(fname)
        return sorted(not_white_files)

    def filters_postfix_white(self, rules: dict) -> list:
        # here, a filter means a k,v in rules dict. k: path, v: white postfix list
        not_white_files = []
        for path, file_post_fix_list in rules.items():
            l = self.filter_postfix_white(path, file_post_fix_list)
            not_white_files.extend(l)
        return not_white_files

    def filter_postfix_black(self, path: str, file_post_fix_list) -> list:
        black_files = []
        for fname in self.files:
            if (fname.startswith(path)):
                for post_fix in file_post_fix_list:
                    if (fname.endswith(post_fix)):
                        black_files.append(fname)
        return sorted(black_files)

    def filters_postfix_black(self, rules: dict) -> list:
        black_files = []
        for path, file_post_fix_list in rules.items():
            l = self.filter_postfix_black(path, file_post_fix_list)
            black_files.extend(l)
        return black_files
