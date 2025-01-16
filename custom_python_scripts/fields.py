"""
Base abstract class for BGP fields in a packet and how to turn themselves into bytes.
"""


class Field:
    """
    Abstract Field.

    A field is a chunk of structured data that can be converted to bytes and parsed from bytes.

    The name is used for readability purposes.
    """

    def __init__(self, value, size: int, name: str) -> None:
        """
        args:
            value: The value of the field.
            size: The size of the field in bytes.
            name: The name of the field.
        """
        self.value = value
        self.size = size
        self.name = name

    def to_bytes(self) -> bytes:
        """
        Convert the field to bytes.
        """
        raise NotImplementedError('Method `to_bytes` must be implemented in subclasses.')

    def parse(self, data: bytes, size: int) -> 'Field':
        """
        Create field object from appropriately structured bytes.
        """
        raise NotImplementedError('Method `parse` must be implemented in subclasses.')

    def __len__(self):
        return self.size


class MetaField(Field):
    """
    Abstract MetaField.

    A MetaField is a field whose value is data about another field or fields.

    It's value can only be derived from other fields and thus the value type should be defined in the `derive` method (see LengthField).
    """

    def __init__(self, dependencies: list[Field], size: int, name: str) -> None:
        """
        args:
            dependencies: The fields that this field depends on.
            size: The size of the field in bytes.
            name: The name of the field.
        """
        super().__init__(None, size, name)
        self.dependencies = dependencies

    def derive(self):
        """
        Derive the value of the field from the dependencies.
        """
        raise NotImplementedError('Method `derive` must be implemented in subclasses.')


class IntField(Field):
    """
    Field for integer values.
    """

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(self.size, 'big')


class StringField(Field):
    """
    Field for string values.
    """

    def __init__(self, value: str, name: str) -> None:
        super().__init__(value, len(value), name)

    def to_bytes(self) -> bytes:
        return self.value.encode()


class ListField(Field):
    """
    Dynamically expanding field that contains other fields.
    """

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

    def __repr__(self) -> str:
        """
        Return a human-readable representation of the field.
        Raw fields such as IntField and StringField are displayed as their byte values in base 16.
            <name>: <value>

        List fields print their name and then each field in the list tabbed under them.
        """
        tab_spaces = 4
        result = self.name + '\n'
        titles_and_values: list[int, Field | MetaField, str, str] = []
        for field in self.value:
            if isinstance(field, ListField):
                if field.size == 0:
                    continue
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
    """
    Field whose value is the sum of the sizes of its dependencies.
    """

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
