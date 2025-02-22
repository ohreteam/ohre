from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmArg import AsmArg
from ohre.misc import Log, utils


def _update_cbs_def_use_vars_reverse(meth: AsmMethod):
    for cb in meth.code_blocks:
        use_vars: set[AsmArg] = set()
        def_vars: set[AsmArg] = set()
        reversed_insts = list(reversed(cb.insts))
        for inst in reversed_insts:
            def_tac, use_tac = inst.get_def_use()
            use_vars |= use_tac
            def_vars |= def_tac
            # a var used and def-ed inside this inst # assume that def op must occur after the use op
            # for var in def_tac: # a=xxx(a not used);...; a used; then for prev inst, a is not used
            # e.g. a = b(c) # then for previous inst, a is not used
            unused_defs = def_tac - use_tac
            use_vars -= unused_defs
        cb.set_use_vars(use_vars)
        cb.set_def_vars(def_vars)
