# coding=utf-8
import re
from dataclasses import dataclass
from typing import Dict

RESULT_EXPR = re.compile(r"\((.+)\)")


@dataclass(repr=True, unsafe_hash=True, frozen=True, eq=True)
class TraceResult:
    local: bool
    route: str = ""
    network_name: str = ""
    zone: str = ""
    country: str = ""

    def __str__(self):
        return f"{self.route}\r\n{self.network_name} {self.zone} {self.country}"

    @classmethod
    def get_from_data(cls, data: Dict):
        is_local = data is None
        if not is_local:
            route = data.get('route', '')
            net_name = data.get('netname', '')
            as_zone = data.get('origin', '')
            country = data.get('country', '')
            return cls(is_local, route, net_name, as_zone, country)
        return cls(is_local)
