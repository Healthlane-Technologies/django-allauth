r"""
    _        ___      __    __  .___________. __    __
 /\| |/\    /   \    |  |  |  | |           ||  |  |  |
 \ ` ' /   /  ^  \   |  |  |  | `---|  |----`|  |__|  |
|_     _| /  /_\  \  |  |  |  |     |  |     |   __   |
 / , . \ /  _____  \ |  `--'  |     |  |     |  |  |  |
 \/|_|\//__/     \__\ \______/      |__|     |__|  |__|

"""

VERSION = (65, 10, 3, "beta", 1)

__title__ = "django-allauth"
__version_info__ = VERSION
__version__ = ".".join(map(str, VERSION[:3])) + (
    "-{}{}".format(VERSION[3], VERSION[4] or "") if VERSION[3] != "final" else ""
)
__author__ = "Zelthy ('Healthlane Technologies')"
__license__ = "MIT"
__copyright__ = "Copyright 2010-2025 Zelthy"
