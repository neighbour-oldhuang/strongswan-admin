import json, os, copy
from pathlib import Path

DATA_FILE = Path("data/config.json")

DEFAULT = {
    "instance": {"installed": False, "auto_start": False},
    "connections": {}
}

def load():
    if DATA_FILE.exists():
        return json.loads(DATA_FILE.read_text())
    return copy.deepcopy(DEFAULT)

def save(data: dict):
    DATA_FILE.parent.mkdir(exist_ok=True)
    DATA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
