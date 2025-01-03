from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.misc import Log, utils


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

        final_nac_blocks: list = list()
        idx_start = 0
        for i in range(len(delimited_id)):
            idx_end = delimited_id[i]
            final_nac_blocks.append(nac_block.get_slice_block(idx_start, idx_end))
            idx_start = idx_end
        return CodeBlocks(final_nac_blocks)
