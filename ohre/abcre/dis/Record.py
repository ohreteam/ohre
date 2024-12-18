from typing import Any, Dict, Iterable, List, Tuple
from ohre.misc import Log
from ohre.abcre.dis.Types import AsmTpye


class Record:
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
                if (AsmTpye.is_uint(ty)):
                    value = int(value, 16)
                else:
                    Log.error(f"ERROR in Record init: ty {ty} name {name} value {value} {type(value)}")
                self.fields[name] = (ty, value)
            else:
                Log.warn(f"invalid line in Record: {line},\nlines: {lines}")

    def debug_deep(self):
        out = f"Record {self.class_name}: "
        for field_name, (ty, value) in self.fields.items():
            out += f"{field_name}({ty}) {value};"
        return out
