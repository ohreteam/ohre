from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.enum.NACTYPE import NACTYPE
from ohre.misc import Log, utils


def get_label2cb(cb_list: List[CodeBlock]) -> Dict[str, CodeBlock]:
    out = dict()
    for cb in cb_list:
        if (cb.len > 0 and cb.insts[0].type == NACTYPE.LABEL):
            out[cb.insts[0].op] = cb
    return out


class ControlFlow():
    def split_native_code_block(blocks: CodeBlocks) -> CodeBlocks:
        assert len(blocks) == 1
        nac_block = blocks.blocks[0]  # should only have one NAC block, not TAC
        delimited_id: list = list()
        for i in range(len(nac_block)):
            nac = nac_block.insts[i]
            if (nac.type == NACTYPE.LABEL):
                delimited_id.append(i)
            elif (nac.type == NACTYPE.COND_JMP or nac.type == NACTYPE.UNCN_JMP or nac.type == NACTYPE.RETURN):
                if (i + 1 < len(nac_block)):
                    delimited_id.append(i + 1)
        delimited_id = sorted(list(set(delimited_id)))
        if (len(nac_block) not in delimited_id):
            delimited_id.append(len(nac_block))

        final_nac_blocks: List[CodeBlock] = list()
        idx_start = 0
        for i in range(len(delimited_id)):
            idx_end = delimited_id[i]
            final_nac_blocks.append(nac_block.get_slice_block(idx_start, idx_end))
            idx_start = idx_end

        for i in range(len(final_nac_blocks)):
            if (i != len(final_nac_blocks) - 1 and
                    (final_nac_blocks[i].inst_len == 0
                     or final_nac_blocks[i].insts[-1].type != NACTYPE.RETURN)):
                final_nac_blocks[i].empty_next_cbs()
                final_nac_blocks[i].add_next_cb(final_nac_blocks[i + 1])
            else:
                final_nac_blocks[i].empty_next_cbs()
            if (i - 1 >= 0 and
                    (final_nac_blocks[i - 1].inst_len == 0
                     or final_nac_blocks[i - 1].insts[-1].type != NACTYPE.RETURN)):
                final_nac_blocks[i].add_prev_cb(final_nac_blocks[i - 1])

        d_label2cb = get_label2cb(final_nac_blocks)
        for i in range(len(final_nac_blocks)):
            if (final_nac_blocks[i].len > 0 and (final_nac_blocks[i].insts[-1].type == NACTYPE.COND_JMP
                                                 or final_nac_blocks[i].insts[-1].type == NACTYPE.UNCN_JMP)):
                label = final_nac_blocks[i].insts[-1].args[0]
                if (label in d_label2cb):
                    final_nac_blocks[i].add_next_cb(d_label2cb[label])
                    d_label2cb[label].add_prev_cb(final_nac_blocks[i])
                else:
                    Log.error(f"jmp to a label NOT exits, {label} d_label2cb {d_label2cb}")

        return CodeBlocks(final_nac_blocks)
