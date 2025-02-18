from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.lifting.LivingVar import _update_cbs_def_use_vars_reverse
from ohre.abcre.dis.TAC import TAC
from ohre.misc import Log, utils


def PeepholeOptimization(meth: AsmMethod):
    Log.info(f"PHO-START {meth.file_class_method_name} inst-{meth.inst_len}", True)
    old_inst_len = meth.inst_len
    for cb in meth.code_blocks:
        PHO_cb(cb)
    if (old_inst_len != meth.inst_len):
        _update_cbs_def_use_vars_reverse(meth)
    for cb in meth.code_blocks:
        PHO_cb_reverse(cb)  # e.g. a=xxx; b=a; a not used later


def PHO_cb(cb: CodeBlock):
    # PHO is short for PeepHole Optimization
    insts = cb.insts
    insts_len = len(insts)

    delete_idx_mask = [False] * insts_len
    # new_idx2inst: Dict[int, TAC] = dict()  # old inst's index to new TAC
    for i in range(insts_len - 1):
        if (delete_idx_mask[i] or delete_idx_mask[i + 1]):
            continue  # if it is about to be replaced, skip it.
        curr_t, next_t = insts[i], insts[i + 1]  # current tac and next tac
        curr_def, curr_use = curr_t.get_def_use_list()
        next_def, next_use = next_t.get_def_use_list()

        # PH-1: a=b; b=a;  =>  a=b;
        if (curr_t.is_simplest_assgin() and next_t.is_simplest_assgin()
                and curr_t.args[0] == next_t.args[1] and curr_t.args[1] == next_t.args[0]):
            delete_idx_mask[i + 1] = True
            continue
        # PH-2: a=xxx (assign tac, def) ; a=yyy (def not used) # delete a=xxx
        # NOTE: assign A but A overwritten immediately
        if (curr_t.type == TACTYPE.ASSIGN and len(curr_def) == 1 and len(next_def) == 1
                and curr_def == next_def and curr_def[0] not in next_use):
            delete_idx_mask[i] = True
            continue
        # PH-3: a=xxx; b=a; a=yyy (yyy not used a)  =>  b=xxx; a=yyy; xxx may be a call or some other
        if (i + 2 < insts_len and next_t.is_simplest_assgin() and len(curr_t.args) and len(insts[i + 2].args)
                and curr_t.args[0] == next_t.args[1] == insts[i + 2].args[0]
                and all(inst.is_arg0_def() for inst in (curr_t, next_t, insts[i + 2]))
                and (not insts[i + 2].is_use(curr_t.args[0]))):
            # print(f"mid_var_def_later {curr_t}; {next_t}; {insts[i + 2]};")
            curr_t.replace_def_var(next_t.args[0])
            delete_idx_mask[i + 1] = True
            continue
        # PH-4: A=B (2-arg-assgin, B has no ref base); A=A["xxx"] (A used and also def) => A=B["xxx"]
        if (curr_t.is_simplest_assgin() and next_t.is_arg0_def()
                and curr_t.args[0] == next_t.args[0] and next_t.args[0] in next_use):
            arg_in = curr_t.args[1]  # var B
            if (arg_in.is_no_ref()):
                next_t.replace_use_var(curr_t.args[0], arg_in)
                delete_idx_mask[i] = True
                continue
    cb.insts = [inst for i, inst in enumerate(insts) if not delete_idx_mask[i]]


def PHO_cb_reverse(cb: CodeBlock):
    insts = cb.insts
    insts_len = len(insts)
    delete_idx_mask = [False] * insts_len

    used_after: set = cb.get_all_next_cbs_use_vars(get_current_cb=False)
    for i in range(insts_len - 1, 0, -1):
        if delete_idx_mask[i] or delete_idx_mask[i - 1]:
            continue
        pre1_t, curr_t = insts[i - 1], insts[i]
        pre1_def, pre1_use = pre1_t.get_def_use_list()
        curr_def, curr_use = curr_t.get_def_use_list()
        # PHO-reverse: pre1: a=xxx; curr: b=a; a not used later
        if (curr_t.is_simplest_assgin()
                and len(curr_def) == len(curr_use) == 1 and len(pre1_def) == 1
                and pre1_def[0] == curr_use[0] and curr_use[0] not in used_after):
            pre1_t.replace_def_var(curr_def[0])
            delete_idx_mask[i] = True
            continue

        def_vars_inst, use_vars_inst = insts[i].get_def_use()  # must update at last
        used_after.update(use_vars_inst)

    cb.insts = [inst for i, inst in enumerate(insts) if not delete_idx_mask[i]]
