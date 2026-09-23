"""helper for the friendly greeter skill.

Pure string building. No file access, no network, no surprises.
"""


def greet(name):
    """Return a short greeting for *name*."""
    clean = str(name).strip() or "friend"
    return "Hello, %s! Good to see you." % clean


def available_greetings():
    return ["morning", "afternoon", "evening"]
