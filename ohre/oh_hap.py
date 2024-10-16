import os
import zipfile
import hashlib
import json
import yara

from . import Log
from . import oh_common


class oh_hap(oh_common.oh_package):
    def __init__(self, path: str):
        Log.info(f"oh_hap init {path}")
        if (not path.endswith(".hap")):
            raise oh_common.ParaNotValid("Not a valid hap type, must .hap")
        super().__init__(path)

