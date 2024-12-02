class BaseRegion:
    # NOTE: for common usage, pos=pos_end of the last region,
    # then use pos_end when unpacking data
    def __init__(self, pos: int):
        self.pos_start = pos
        self.pos_end = pos

    def get_pos_start(self) -> int:
        return self.pos_start

    def get_pos_end(self) -> int:
        return self.pos_end

    def get_pos(self) -> tuple[int, int]:
        return self.pos_start, self.pos_end

    @classmethod
    def _get_class_offset(cls, buf, pos):
        ret_class = cls(buf, pos)
        return ret_class, ret_class.pos_end
