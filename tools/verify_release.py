"""Проверяет подпись manifest.json публичным ключом из update.go и контрольную сумму архива — до публикации."""
import base64
import hashlib
import json
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pub = re.search(r'updatePubKey = "([^"]+)"', open("update.go", encoding="utf-8").read()).group(1)
man = open("manifest.json", "rb").read()
Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(open("manifest.json.sig").read().strip()), man)
m = json.loads(man)
assert m["version"] == sys.argv[1], (m["version"], sys.argv[1])
assert hashlib.sha256(open(m["file"], "rb").read()).hexdigest() == m["sha256"], "sha256"
print("подпись и контрольная сумма в порядке:", m["file"], m["version"])
