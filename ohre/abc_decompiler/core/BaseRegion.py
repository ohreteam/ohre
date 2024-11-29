class BaseRegion(object):
    def __init__(self, pos: int = 0):
        self.pos_start = pos
        self.pos_end = pos

    def get_pos_start(self) -> int:
        return self.pos_start

    def get_pos_end(self) -> int:
        return self.pos_end

    def get_pos(self) -> tuple[int, int]:
        return self.pos_start, self.pos_end
