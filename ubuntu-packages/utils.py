import json
import uuid


# Adapted from https://stackoverflow.com/a/25935321/12940655
class NoIndent:
    def __init__(self, value):
        self.value = value


# Adapted from https://stackoverflow.com/a/25935321/12940655
class NoIndentEncoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        super(NoIndentEncoder, self).__init__(*args, **kwargs)
        self.kwargs = dict(kwargs)
        del self.kwargs['indent']
        self._replacement_map = {}

    def _do_replacement_on_part(self, part: str):
        if part.startswith('"@@'):
            try:
                return self._replacement_map[part[3:-3]]
            except KeyError:
                return part
        else:
            return part

    def default(self, o):
        if isinstance(o, NoIndent):
            key = uuid.uuid4().hex
            self._replacement_map[key] = json.dumps(o.value, **self.kwargs)
            return '@@%s@@' % (key,)
        else:
            return super().default(o)

    def iterencode(self, o, _one_shot=False):
        parts = super().iterencode(o, _one_shot)
        return map(self._do_replacement_on_part, parts)
