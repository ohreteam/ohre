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

    def extract_all_to(self, unzip_folder: str, unzip_sub_hap=True):
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
        except zipfile.BadZipFile:
            Log.warn(f"{self.sha1} Bad ZIP file, {self.file_path}")
            return False
