from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.misc import Log, utils


class AsmRecord(DebugBase):
    # fields in Class
    def __init__(self, lines: List[str]):
        self.module_name: str = ""  # full str at 1st line except .record, {, whitespace, and &
        self.fields: Dict[str, Tuple[str, Any]] = dict()  # k: str: field name; v: (type, value)
        for line in lines:
            line = line.strip()
            if ("}" in line):  # the last line
                break
            elif ("{" in line and ".record" in line):  # 1st line
                parts = line.split(" ")
                self.module_name = parts[1].strip()
            elif ("=" in line):
                parts = line.split("=")
                ty, name = parts[0].split(" ")[0].strip(), parts[0].split(" ")[1].strip()
                value = parts[1].strip()
                if (AsmTypes.is_uint(ty)):
                    value = int(value, 16)
                else:
                    Log.error(f"ERROR in AsmRecord init: ty {ty} name {name} value {value} {type(value)}")
                self.fields[name] = (ty, value)
            else:
                Log.warn(f"invalid line in AsmRecord: {line},\nlines: {lines}")
        # file+class name like: &entry.src.main.ets.entryability.EntryAbility&
        self.module_name = utils.strip_sted_str(self.module_name, "&", "&")

    def _debug_str(self) -> str:
        out = f"AsmRecord: {self.module_name}:"
        for field_name, (ty, value) in self.fields.items():
            if (isinstance(value, int)):
                out += f"{field_name}({ty}) {hex(value)}; "
            else:
                out += f"{field_name}({ty}) {value}; "
        return out

    def _debug_vstr(self) -> str:
        return self._debug_str()


if __name__ == "__main__":
    test1 = [".record a..ohpm.b@1.2.3.a.b.umd.c {",
             "	u8 umd = 0x0",
             "}"]

    test2 = [".record &entry.src.main.ets.entryability.EntryAbility& {",
             "	u32 scopeNames = 0x15e7",
             "}"]
    t = AsmRecord(test1)
    print(f"test1: {t}")
    t = AsmRecord(test2)
    print(f"test2: {t}")
