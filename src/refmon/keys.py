"""Per-device secrets. The Observe fingerprint key and the pseudonym key are random per device;
a constant key would make fingerprints reversible by anyone who reads the source."""

import os


def new_device_key() -> bytes:
    return os.urandom(32)


# The key the replay tools, the robustness generator and the tests use for synthetic lab fixtures
# (review 2026-11, item 8). It is explicit and named so that no production class has a default
# key; its bytes are the old default, so recorded evaluation outputs stay byte-identical and the
# decisions are the same (they do not depend on the key). It is never a device key: the privacy
# audit attacks exactly this value.
LAB_REPLAY_KEY = b"refmon-device-key"
