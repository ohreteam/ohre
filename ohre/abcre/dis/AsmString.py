from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log


class AsmString(DebugBase):
    def __init__(self, line: str):
        idx = line.find(", ")
        assert idx > 2 and idx < len(line) - 2
        self.offset = int(line[:idx].split(":")[1], 16)
        remain_line = line[idx + 2:]
        idx2 = remain_line.find(":")
        self.name_value = remain_line[idx2 + 1:]

    def _debug_str(self):
        out = f"AsmString({hex(self.offset)}) {len(self.name_value)} {self.name_value}"
        return out

    def _debug_vstr(self):
        return self._debug_str()
