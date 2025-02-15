from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.misc import Log


class AsmRecord(DebugBase):
    # fields in Class
    def __init__(self, lines: List[str]):
        self.file_class_name: str = ""  # full str at 1st line except .record, {, whitespace, and &
        self.file_name: str = ""
        self.class_name: str = ""
        self.fields: Dict[str, Tuple[str, Any]] = dict()  # k: str: field name; v: (type, value)
        for line in lines:
            line = line.strip()
            if ("}" in line):  # the last line
                break
            elif ("{" in line and ".record" in line):  # 1st line
                parts = line.split(" ")
                self.file_class_name = parts[1].strip()
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
        if (self.file_class_name.startswith("&")):
            self.file_class_name = self.file_class_name[1:]
        if (self.file_class_name.endswith("&")):
            self.file_class_name = self.file_class_name[:-1]
        file_postfix_idx = self.file_class_name.find(".ets")
        if (not file_postfix_idx > 0):
            file_postfix_idx = self.file_class_name.find(".src")
        if (file_postfix_idx > 0):
            self.file_name = self.file_class_name[:file_postfix_idx + len(".ets")].strip()
            self.class_name = self.file_class_name[file_postfix_idx + len(".ets") + 1:].strip()

    @property
    def module_name(self) -> str:
        return self.file_class_name

    def _debug_str(self) -> str:
        out = f"AsmRecord: {self.file_class_name} file_name({len(self.file_name)}) {self.file_name} \
class_name({len(self.class_name)}) {self.class_name}: "
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
