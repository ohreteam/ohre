from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log


class AsmString(DebugBase):
    def __init__(self, lines: List[str]):
        line = ""
        for s in lines:
            line += s
        line = line.strip()
        assert line[0] == "[" and line[-1] == "]"
        line = line[1:-1]
        idx = line.find(", ")
        assert idx > 2 and idx < len(line) - 2
        self.offset = int(line[:idx].split(":")[1], 16)
        line_remain = line[idx + 2:]
        idx2 = line_remain.find(":")
        self.name_value = line_remain[idx2 + 1:]

    def _debug_str(self):
        out = f"AsmString({hex(self.offset)}) {len(self.name_value)} {self.name_value}"
        return out

    def _debug_vstr(self):
        return self._debug_str()
