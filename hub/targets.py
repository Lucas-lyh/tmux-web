"""Parse a target before looking up its availability."""
import re

NODE_NAME = re.compile(r'^[\w.\-]{1,32}$', re.UNICODE)
SESSION_NAME = re.compile(r'^[\w.\-]{1,64}$', re.UNICODE)


def split_target(value):
    if ':' not in value:
        return None, value
    node, _, session = value.partition(':')
    if not NODE_NAME.fullmatch(node) or not SESSION_NAME.fullmatch(session):
        raise ValueError('invalid node session name')
    return node, session
