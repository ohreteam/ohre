import copy
import json
import os
from typing import Any, Dict, Iterable, List, Tuple

import yaml

import ohre
from ohre.misc import Log, utils


class ISA:
    def __init__(self, isa_file_path: str):
        self.ori_d: Dict = utils.read_dict_from_yaml_file(isa_file_path)
        assert self.ori_d is not None

        self.prefixes: Dict | None = None
        self.prefixes = self._get_prefixes_dict()
        assert self.prefixes is not None
        Log.info(f"[ISA] self.prefixes {len(self.prefixes)} {self.prefixes}")

        self.opstr2infod: Dict[str, Dict] | None = None
        self.opstr2infod = self._get_opstr_dict()
        assert self.opstr2infod is not None
        Log.info(f"[ISA] self.opstr2infod {len(self.opstr2infod)} keys: {self.opstr2infod.keys()}")

    def _get_prefixes_dict(self) -> Dict:
        if (self.prefixes is not None):
            return self.prefixes
        ret = {}
        for sub_d in self.ori_d["prefixes"]:
            ret[sub_d["name"]] = {"description": sub_d["description"], "opcode_idx": sub_d["opcode_idx"]}
        return ret

    def _get_prefix_opcode(self, prefix: str) -> int:
        if (prefix in self.prefixes.keys()):
            return self.prefixes[prefix]["opcode_idx"]
        return -1

    def _get_opstr_dict(self) -> Dict[str, Dict]:
        ret = dict()
        for group in self.ori_d["groups"]:
            title = group["title"] if "title" in group.keys() else None
            assert len(title) > 0 and isinstance(title, str)
            description: str = group["description"].strip() if "description" in group.keys() else None
            verification: List | None = group["verification"] if "verification" in group.keys() else None
            exceptions: List | None = group["exceptions"] if "exceptions" in group.keys() else None
            properties_common: List | None = group["properties"] if "properties" in group.keys() else None
            namespace: str = group["namespace"].strip() if "namespace" in group.keys() else None
            pseudo: str = group["pseudo"].strip() if "pseudo" in group.keys() else None
            semantics: str = group["semantics"].strip() if "semantics" in group.keys() else None

            assert "instructions" in group.keys()
            for inst in group["instructions"]:
                assert "sig" in inst.keys() and "opcode_idx" in inst.keys()
                opstr = inst["sig"].split(" ")[0].strip()
                opcode_idx = inst["opcode_idx"]

                acc = inst["acc"] if "acc" in inst.keys() else None
                format = inst["format"] if "format" in inst.keys() else None
                prefix = inst["prefix"] if "prefix" in inst.keys() else None
                properties_inst: List | None = inst["properties"] if "properties" in inst.keys() else None
                properties = None
                if (properties_inst is not None and properties_common is not None):
                    properties = copy.deepcopy(properties_common + properties_inst)
                elif (properties_inst is not None and properties_common is None):
                    properties = copy.deepcopy(properties_inst)
                elif (properties_inst is None and properties_common is not None):
                    properties = copy.deepcopy(properties_common)

                if (prefix is not None):  # final_opcode = prefix_opcode|op_code # concat, not 'or'
                    prefix_opcode = self._get_prefix_opcode(prefix)
                    assert prefix_opcode != -1
                    opcode_idx = [(prefix_opcode << 8) + op_code for op_code in opcode_idx]

                ret[opstr] = {
                    "sig": inst["sig"],
                    "acc": acc, "opcode_idx": opcode_idx, "prefix": prefix, "format": format, "title": title,
                    "description": description, "verification": verification, "exceptions": exceptions,
                    "properties": properties, "namespace": namespace, "pseudo": pseudo, "semantics": semantics}
        return ret

    def get_opcodes(self, opstr: str) -> List | None:
        opcode_info_d = self.get_opstr_info_dict(opstr)
        if (opcode_info_d is None):
            return None
        else:
            if ("opcode_idx" in opcode_info_d.keys()):
                return opcode_info_d["opcode_idx"]
            else:
                Log.warn(f"[ISA] opstr {opstr}, opcode_idx not in {opcode_info_d.keys()}")
                return None

    def get_opstr_info_dict(self, opstr: str) -> Dict | None:
        if opstr in self.opstr2infod.keys():
            return self.opstr2infod[opstr]
        else:
            Log.warn(f"[ISA] opstr NOT hit directly, opstr {opstr}, remove prefix and match again", True)
            for key_opstr in self.opstr2infod.keys():
                opstr_rhs = key_opstr
                tmp = opstr_rhs.split(".")
                if (len(tmp) > 1 and opstr == tmp[1]):
                    Log.warn(f"[ISA] opstr change: {opstr} -> {key_opstr}", True)
                    return self.opstr2infod[key_opstr]
            return None


if __name__ == "__main__":
    ohre.set_log_print(True)
    d = utils.read_dict_from_yaml_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "isa.yaml"))
    isa = ISA(os.path.join(os.path.dirname(os.path.abspath(__file__)), "isa.yaml"))
    # print(json.dumps(isa.ori_d["groups"], indent=4))
    assert isa.get_opcodes("deprecated.getiteratornext") == [0xfc02]
    assert isa.get_opcodes("callruntime.notifyconcurrentresult") == [0xfb00]
    for ins_str in ["mov", "callruntime.definefieldbyindex", "isin", "jequndefined"]:
        print(f"{ins_str}: {utils.hexstr(isa.get_opcodes(ins_str))} {isa.get_opstr_info_dict(ins_str)}")
    title_set = set()
    for opstr in isa.opstr2infod.keys():
        title_set.add(isa.opstr2infod[opstr]["title"])
    print(f"{len(title_set)} {title_set}")
