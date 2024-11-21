class Field:
    def __init__(self, value, size: int, name: str) -> None:
        self.value = value
        self.size = size
        self.name = name

    def to_bytes(self) -> bytes:
        raise NotImplementedError('Method `to_bytes` must be implemented in subclasses.')

    def __len__(self):
        return self.size


class MetaField(Field):
    def __init__(self, dependencies: list[Field], size: int, name: str) -> None:
        super().__init__(None, size, name)
        self.dependencies = dependencies

    def derive(self):
        raise NotImplementedError('Method `derive` must be implemented in subclasses.')


class IntField(Field):
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(self.size, 'big')


class StringField(Field):
    def __init__(self, value: str, name: str) -> None:
        super().__init__(value, len(value), name)

    def to_bytes(self) -> bytes:
        return self.value.encode()


class ListField(Field):
    def __init__(self, value: list[Field | MetaField], name: str) -> None:
        size = 0
        for val in value:
            size += val.size
        super().__init__(value, size, name)

    def to_bytes(self) -> bytes:
        return b''.join([val.to_bytes() for val in self.value])

    def append(self, value: Field | MetaField) -> None:
        self.value.append(value)
        self.size += value.size

    def extend(self, values: list[Field | MetaField]) -> None:
        self.value.extend(values)
        for val in values:
            self.size += val.size

    def __repr__(self):
        tab_spaces = 4
        result = self.name + '\n'
        titles_and_values: list[int, Field | MetaField, str, str] = []
        for field in self.value:
            if isinstance(field, ListField):
                lines = [val for val in repr(field).split('\n') if val]
                for line in lines:
                    depth = 1 + ((len(line) - len(line.lstrip())) // tab_spaces)
                    line = line.strip()
                    tokens = line.split(':')
                    title = ''
                    value = ''
                    if len(tokens) == 1:
                        title = tokens[0]
                    elif len(tokens) == 2:
                        try:
                            int(tokens[-1], 16)
                            title, value = tokens
                        except ValueError:
                            title = f'{tokens[0].strip()}: {tokens[1].strip()}'
                    prefix_str = ' ' * (tab_spaces * depth)
                    titles_and_values.append((prefix_str + title, value))
            else:
                depth = 1
                prefix_str = ' ' * (tab_spaces * depth)
                titles_and_values.append((prefix_str + field.name, field.to_bytes().hex().lower()))
        title_l_just = max([len(title) for title, _ in titles_and_values]) + 1
        value_r_just = max([len(value) for _, value in titles_and_values]) + 1

        for title, value in titles_and_values:
            if not value:
                result += f'{title}\n'
            else:
                result += f'{title.ljust(title_l_just)}:{value.rjust(value_r_just)}\n'
        return result


class LengthField(MetaField):
    def derive(self) -> int:
        if self.dependencies is None:
            raise ValueError('LengthField must have dependencies.')
        length = 0
        for field in self.dependencies:
            length += len(field)
        return length

    def to_bytes(self) -> bytes:
        if self.dependencies is None:
            raise ValueError('LengthField must have dependencies.')
        return self.derive().to_bytes(self.size, 'big')
