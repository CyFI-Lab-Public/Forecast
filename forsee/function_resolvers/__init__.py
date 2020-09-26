import logging
from typing import Optional

from angr import Project

from .elf_resolver import Elf32Resolver
from .pe_resolver import PeResolver
from .resolver_base import FunctionResolver

log = logging.getLogger(__name__)

resolvers = [Elf32Resolver, PeResolver]


def get_compatible_resolver(
    start_addr: int, proj: Project
) -> Optional[FunctionResolver]:
    resolver = None
    for r in resolvers:
        if r.is_compatible(start_addr, proj):
            resolver = r(proj)
            break
    if resolver is None:
        log.warning("Could not find compatible function resolver")
        return None
    return resolver
