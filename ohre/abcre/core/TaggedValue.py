import ohre.core.ohoperator as op
import ohre.misc.const as const
from ohre.misc import Log


class TaggedValue:
    def __init__(self, tag_value, data=None):
        if ((not isinstance(tag_value, int)) or tag_value > const.UINT8MAX):
            Log.error(f"TaggedValue tag_value is NOT valid, tag_value={tag_value}")
        self.tag_value = tag_value  # uint8_t
        self.data = data

    @property
    def tag(self):
        return self.tag_value

    @property
    def value(self):
        return self.data

    def set_tag_value(self, tag_value: int):
        if (tag_value > const.UINT8MAX):
            Log.error(f"TaggedValue tag_value is NOT valid, tag_value={tag_value}")
        self.tag_value = tag_value

    def set_data(self, data):
        self.data = data

    def set_tag_value_data(self, tag_value, data):
        self.set_tag_value(tag_value)
        self.set_data(data)

    def get_data_as_string(self):
        return op._uint8_t_array_to_string(self.data)

    def __str__(self):
        return f"{self.tag_value} {self.data}"
