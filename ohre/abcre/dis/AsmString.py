from typing import Any, Dict, Iterable, List, Tuple
from ohre.misc import Log
from ohre.abcre.dis.AsmTypes import AsmTpye


class AsmString:
    def __init__(self, line: str):
        idx = line.find(", ")
        assert idx > 2 and idx < len(line) - 2
        self.offset = int(line[:idx].split(":")[1], 16)
        self.name_value = line[idx + 2:].split(":")[1]

    def __str__(self):
        return self.debug_deep()

    def debug_deep(self):
        out = f"AsmString {hex(self.offset)} {self.name_value}"
        return out
