from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.misc import Log


class AsmString:
    def __init__(self, line: str):
        idx = line.find(", ")
        assert idx > 2 and idx < len(line) - 2
        self.offset = int(line[:idx].split(":")[1], 16)
        remain_line = line[idx + 2:]
        idx2 = remain_line.find(":")
        self.name_value = remain_line[idx2 + 1:]

    def __str__(self):
        return self.debug_deep()

    def debug_deep(self):
        out = f"AsmString({hex(self.offset)}) {len(self.name_value)} {self.name_value}"
        return out
