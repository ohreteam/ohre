from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.misc import Log


class AsmRecord:
    # fields in Class
    def __init__(self, lines: List[str]):
        self.class_name: str = ""
        self.fields: Dict[Tuple[str, Any]] = dict()  # k: field name; v: (type, value)
        for line in lines:
            line = line.strip()
            if ("}" in line):
                return
            elif ("{" in line and ".record" in line):
                parts = line.split(" ")
                self.class_name = parts[1].split("@")[0]
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

    def debug_deep(self):
        out = f"AsmRecord {self.class_name}: "
        for field_name, (ty, value) in self.fields.items():
            out += f"{field_name}({ty}) {value};"
        return out
