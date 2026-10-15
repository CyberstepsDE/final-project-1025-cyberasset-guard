"""Version comparison that tolerates real-world version strings (7.4p1, 1.0.1g, 2.0-rc1)."""
import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_PRE_RELEASE = {"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot"}
_PAD = (1, 0)


def _key(version: str) -> list[tuple[int, int | str]]:
    key: list[tuple[int, int | str]] = []
    for token in _TOKEN.findall(version.lower()):
        if token.isdigit():
            key.append((1, int(token)))
        elif token in _PRE_RELEASE:
            key.append((0, token))  # 2.0rc1 < 2.0
        else:
            key.append((2, token))  # 7.4p1 > 7.4, 1.0.1g > 1.0.1
    return key


_EPOCH = re.compile(r"^\s*(\d+):(.+)$")


def _split_epoch(version: str) -> tuple[int, str]:
    """Debian-style "1:2.0" -> (1, "2.0"); no epoch means epoch 0."""
    match = _EPOCH.match(version)
    return (int(match.group(1)), match.group(2)) if match else (0, version)


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1. Missing parts count as zero, so 1.0 == 1.0.0; a higher epoch wins."""
    (ea, a), (eb, b) = _split_epoch(a), _split_epoch(b)
    if ea != eb:
        return -1 if ea < eb else 1
    ka, kb = _key(a), _key(b)
    length = max(len(ka), len(kb))
    ka += [_PAD] * (length - len(ka))
    kb += [_PAD] * (length - len(kb))
    for x, y in zip(ka, kb, strict=True):          # both padded to `length` above
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        return -1 if x[1] < y[1] else 1  # type: ignore[operator]
    return 0


def in_range(
    version: str,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """True if version lies inside the NVD versionStart*/versionEnd* bounds."""
    if start_including and compare_versions(version, start_including) < 0:
        return False
    if start_excluding and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and compare_versions(version, end_including) > 0:
        return False
    if end_excluding and compare_versions(version, end_excluding) >= 0:
        return False
    return True
