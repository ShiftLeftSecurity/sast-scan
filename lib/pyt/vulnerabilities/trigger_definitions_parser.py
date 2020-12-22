import json
from collections import namedtuple

Definitions = namedtuple("Definitions", ("sources", "sinks"))

Source = namedtuple("Source", ("trigger_word", "source_type"))

Rule = namedtuple(
    "Rule",
    (
        "name",
        "code",
        "severity",
        "cwe_category",
        "owasp_category",
        "sources",
        "sinks",
        "message_format",
    ),
)


class Sink:
    def __init__(
        self,
        sink_type,
        trigger,
        *,
        unlisted_args_propagate=True,
        arg_dict=None,
        sanitisers=None,
    ):
        self.sink_type = sink_type
        self._trigger = trigger
        self.sanitisers = sanitisers or []
        self.arg_list_propagates = not unlisted_args_propagate

        if trigger[-1] != "(":
            if self.arg_list_propagates or arg_dict:
                return

        arg_dict = {} if arg_dict is None else arg_dict
        self.arg_position_to_kwarg = {
            position: name
            for name, position in arg_dict.items()
            if position is not None
        }
        self.kwarg_list = set(arg_dict.keys())

    def arg_propagates(self, index):
        kwarg = self.get_kwarg_from_position(index)
        return self.kwarg_propagates(kwarg)

    def kwarg_propagates(self, keyword):
        in_list = keyword in self.kwarg_list
        return self.arg_list_propagates == in_list

    def get_kwarg_from_position(self, index):
        return self.arg_position_to_kwarg.get(index)

    def __str__(self):
        return f"Sink: Type: {self.sink_type}, Trigger: {self._trigger}"

    @property
    def all_arguments_propagate_taint(self):
        if self.kwarg_list:
            return False
        return True

    @property
    def call(self):
        if self._trigger[-1] == "(":
            return self._trigger[:-1]
        return None

    @property
    def trigger_word(self):
        return self._trigger

    @classmethod
    def from_json(cls, sink_type, key, data):
        return cls(sink_type=sink_type, trigger=key, **data)


def parse(trigger_word_file):
    """Parse the file for source and sink definitions.

    Returns:
       A definitions tuple with sources and sinks.
    """
    with open(trigger_word_file, mode="r", encoding="utf-8") as fd:
        triggers_dict = json.load(fd)
    sources = []
    sinks = []
    for st, sv in triggers_dict["sources"].items():
        for tw in sv:
            sources.append(Source(tw, st))
    for sink_type, trigger_obj in triggers_dict["sinks"].items():
        for trigger, data in trigger_obj.items():
            sinks.append(Sink.from_json(sink_type, trigger, data))
    return Definitions(sources, sinks)


def parse_rules(taint_config_file):
    """Parse taint config to produce rules

    Returns:
       List of rules
    """
    with open(taint_config_file, mode="r", encoding="utf-8") as fd:
        taints_dict = json.load(fd)
    rules = []
    for r in taints_dict.get("rules"):
        rules.append(
            Rule(
                r["name"],
                r["code"],
                r["severity"],
                r["cwe_category"],
                r["owasp_category"],
                r["sources"],
                r["sinks"],
                r["message_format"],
            )
        )
    return rules
