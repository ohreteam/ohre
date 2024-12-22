import os

from ohre.abcre.dis.ISA import ISA
from ohre.abcre.enum.BaseEnum import BaseEnum
from ohre.misc import Log, utils


def _value_in_key_of_dict(d: dict, key, value):
    if (key in d.keys() and d[key] is not None and value in d[key]):
        return True
    return False


class NACTYPE(BaseEnum):
    def __init__(self):
        super().__init__()

    ASSIGN = 0  # at most 3 arg
    COND_JMP = 1  # 3 arg
    UNCN_JMP = 2  # 1 arg # unconditional
    CALL = 3  # 1 or more arg
    COND_THROW = 4  # 3 arg
    UNCN_THROW = 5  # 1 arg
    RETURN = 6  # 1 arg
    IMPORT = 11
    LABEL = 12
    NOP = 20
    # >= 30: need more analysis
    CMP_INST = 30  # comparation instructions
    OBJ_VISIT = 31  # object visitors
    DEFINITION = 32  # definition instuctions
    ITER = 33
    OBJ_LD = 34
    OBJ_CREATE = 35
    BINARY_OP = 40
    UNARY_OP = 41
    MOV = 42
    ACC_LD = 43
    ACC_ST = 44
    # default:
    UNKNOWN = 99

    isa: ISA | None = None

    @classmethod
    def get_NAC_type(cls, op: str) -> int:
        if (cls.isa is None):
            NACTYPE.init_from_ISAyaml(os.path.join(os.path.dirname(os.path.abspath(__file__)), "isa.yaml"))
        op = op.strip()
        if (op.endswith(":")):
            return NACTYPE.LABEL

        info_d = cls.isa.get_opstr_info_dict(op)
        # print(f"op {op} info_d {info_d}")
        assert info_d is not None and "title" in info_d.keys()
        if (_value_in_key_of_dict(info_d, "properties", "return")):
            return NACTYPE.RETURN
        elif (op == "nop"):
            return NACTYPE.NOP
        # unconditional jump
        elif (op == "jmp"):
            return NACTYPE.UNCN_JMP
        # conditional jump
        elif (_value_in_key_of_dict(info_d, "properties", "jump") and _value_in_key_of_dict(info_d, "properties", "conditional")):
            return NACTYPE.COND_JMP
        elif (_value_in_key_of_dict(info_d, "properties", "conditional_throw")):
            return NACTYPE.COND_THROW
        elif ("prefix" in info_d.keys() and info_d["prefix"] == "throw"):
            return NACTYPE.UNCN_THROW
        elif ("call instructions" in info_d["title"] or "call runtime functions" in info_d["title"]):
            return NACTYPE.CALL
        # TODO: future work
        elif ("comparation instructions" in info_d["title"]):
            return NACTYPE.CMP_INST
        elif ("object visitors" in info_d["title"].lower()):
            return NACTYPE.OBJ_VISIT
        elif ("definition instuctions" in info_d["title"].lower()):
            return NACTYPE.DEFINITION
        elif ("constant object loaders" in info_d["title"].lower()):
            return NACTYPE.OBJ_LD
        elif ("object creaters" in info_d["title"].lower()):
            return NACTYPE.OBJ_CREATE
        elif ("iterator instructions" in info_d["title"].lower()):
            return NACTYPE.ITER
        elif ("binary operations" in info_d["title"].lower()):
            return NACTYPE.BINARY_OP
        elif ("unary operations" in info_d["title"].lower()):
            return NACTYPE.UNARY_OP
        elif ("Dynamic move register-to-register".lower() in info_d["title"].lower()):
            return NACTYPE.MOV
        elif ("load accumulator" in info_d["title"].lower()):
            return NACTYPE.ACC_LD
        elif ("store accumulator" in info_d["title"].lower()):
            return NACTYPE.ACC_ST
        Log.warn(f"[NACTYPE] op {op} get UNKNOWN type")
        return NACTYPE.UNKNOWN

    @classmethod
    def init_from_ISAyaml(cls, yaml_path: str):
        cls.isa = ISA(yaml_path)


if __name__ == "__main__":
    NACTYPE.init_from_ISAyaml(os.path.join(os.path.dirname(os.path.abspath(__file__)), "isa.yaml"))
    # for inst in [
    #     "mov", "return", "ldobjbyname", "jeqz", "jnez", "jstricteq", "jnstricteq", "throw", "throw.notexists",
    #         "throw.ifnotobject"]:
    #     print(f"inst {inst}: {NACTYPE.get_code_name(NACTYPE.get_NAC_type(inst))}")
    print(f"op total count: {len(NACTYPE.isa.opstr2infod)}")
    for inst in NACTYPE.isa.opstr2infod.keys():
        print(f"inst {inst}: {NACTYPE.get_code_name(NACTYPE.get_NAC_type(inst))}")
        assert NACTYPE.get_code_name(NACTYPE.get_NAC_type(inst)) != "UNKNOWN"
