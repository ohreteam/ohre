from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.misc import Log, utils


def _update_cbs_def_use_vars_reverse(meth: AsmMethod):
    for cb in meth.code_blocks:
        use_vars: set = set()
        def_vars: set = set()
        for inst in reversed(cb.insts):
            def_tac, use_tac = inst.get_def_use()
            use_vars.update(use_tac)
            def_vars.update(def_tac)
            # a var used and def-ed inside this inst # assume that def op must occur after the use op
            for var in def_tac: # a=xxx(a not used);...; a used; then for prev inst, a is not used
                if(var not in use_tac): # e.g. a = b(c) # then for previous inst, a is not used
                    use_vars.discard(var)
        cb.set_use_vars(use_vars)
        cb.set_def_vars(def_vars)
