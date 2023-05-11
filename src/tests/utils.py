from pathlib import Path


def get_current_dir():
    return Path(__file__).parent.resolve()


def get_kb_dir():
    return get_current_dir() / "kb"
