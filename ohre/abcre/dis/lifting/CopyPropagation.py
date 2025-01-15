from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.lifting.LivingVar import _update_method_cbs_def_use_vars
from ohre.abcre.dis.TAC import TAC


def CopyPropagation(meth: AsmMethod):
    print(f"CPro-START {meth.name} {meth.level_str} {meth._debug_vstr()}")
    for cb in meth.code_blocks:
        CPro_cb(cb)
    print(f"CPro-END {meth.name} {meth.level_str} {meth._debug_vstr()}")


def CPro_cb(cb: CodeBlock):
    print(f"\nCPro_cb cb: {cb._debug_str()}")
    var2val: Dict[AsmArg, AsmArg] = dict()
    for i in range(cb.get_insts_len()):
        inst = cb.insts[i]
        inst.copy_propagation(var2val)
        if (inst.is_simple_assgin() or inst.type == TACTYPE.IMPORT):
            var2val[inst.args[0]] = inst.args[1]
            print(f"inst {inst};  var2val {var2val}")
        # TODO: FUNC_IDX = 12 support call
