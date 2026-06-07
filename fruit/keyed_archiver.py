from plistlib import UID

class KeyedArchiveException(Exception):
    """
    Error in the keyed archive
    """
    pass


def read_archive_properties(archive, path):
    # get the root
    top = archive.get("$top", None)
    objects = archive.get("$objects", None)
    if top is None or objects is None:
        raise KeyedArchiveException()
    for key in path:
        if key not in top:
            return None
        top = top[key]
        if isinstance(top, UID):
            top = objects[top]
    return top