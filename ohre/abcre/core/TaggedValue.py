import ohre.core.operator as op


class TaggedValue:
    def __init__(self, tag_value, data=None):
        self.tag_value = tag_value
        self.data = data

    @property
    def tag(self):
        return self.tag_value

    @property
    def value(self):
        return self.data

    def set_tag_value(self, tag_value):
        self.tag_value = tag_value

    def set_data(self, data):
        self.data = data

    def set_tag_value_data(self, tag_value, data):
        self.tag_value = tag_value
        self.data = data

    def get_data_to_string(self):
        return op._uint8_t_array_to_string(self.data)

    def __str__(self):
        return f"{self.tag_value} {self.data}"
