"""Spelling correction for questions.

Words are compared with a vocabulary taken from the knowledge graph (names, glossary terms,
products, descriptions) and an English word list. A word that either of them knows is never
changed, so correct questions pass through untouched. Every change is reported to the user.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from rapidfuzz import process
from rapidfuzz.distance import OSA

_WORD = re.compile(r"[A-Za-z][A-Za-z'&+#]*")
# English words rarer than this in the word list are mostly names and typos
_ENGLISH_MIN = 60

# "CEV-2021-44228", "CVE 2O21 44228", "cewe 89", "capce-66": letters of the prefix swapped,
# doubled or missing, and O / l typed for 0 / 1 inside the number
_ID_TYPOS = (
    (re.compile(r"\b(?:cve|cev|vce|vec|ecv|cvve|ccve|cvee|cbe|cvr|cvw)s?[-\s_:/.]*"
                r"([12][0-9OoIl]{3})[-\s_:/.]+([0-9OoIl]{4,7})\b", re.I), "CVE-{0}-{1}"),
    (re.compile(r"\b(?:cve|cev|vce)([12]\d{3})(\d{4,7})\b", re.I), "CVE-{0}-{1}"),
    (re.compile(r"\b(?:cwe|cew|wce|ewc|cwwe|ccwe|cwee|cwr)[-\s_:/.]*([0-9OoIl]{1,4})\b", re.I), "CWE-{0}"),
    (re.compile(r"\b(?:capec|capce|cpaec|acpec|cape|capc|capecc|cappec|caepc|kapec)[-\s_:/.]*([0-9]{1,4})\b",
                re.I), "CAPEC-{0}"),
)


def fix_identifiers(message: str) -> tuple[str, list[tuple[str, str]]]:
    changes: list[tuple[str, str]] = []
    for pattern, template in _ID_TYPOS:
        def replace(match: re.Match) -> str:
            parts = [re.sub("[Il]", "1", re.sub("[Oo]", "0", g)) for g in match.groups()]
            fixed = template.format(*parts)
            plain = re.sub(r"[-\s_:/.]", "", match.group(0)).upper()
            if plain != fixed.replace("-", ""):
                changes.append((match.group(0), fixed))
                return fixed
            return match.group(0)
        message = pattern.sub(replace, message)
    return message, changes


_english: Counter | None = None


def english_words() -> Counter:
    """Frequency list bundled with pyspellchecker (offline)."""
    global _english
    if _english is None:
        try:
            from spellchecker import SpellChecker
            words = SpellChecker(language="en").word_frequency
            _english = Counter({w: words[w] for w in words.words() if words[w] >= _ENGLISH_MIN})
        except ImportError:
            _english = Counter()
    return _english


class SpellCorrector:
    def __init__(self, texts: Iterable[tuple[str, int]], extra: Iterable[str] = (),
                 brands: Iterable[str] = (), nicknames: Iterable[str] = ()):
        """``texts``: (text, weight); names weigh more than descriptions."""
        counts: Counter = Counter()
        for text, weight in texts:
            for word in _WORD.findall(text or ""):
                if len(word) > 2:
                    counts[word.lower()] += weight
        # a word seen once in running text may itself be a misspelling
        self.domain = Counter({w: c for w, c in counts.items() if c >= 3})
        for word in extra:
            self.domain[word.lower()] += 50
        # product / vendor words are known, but short ones are never suggested ("elon" is
        # not a misspelt "ewon")
        self._short_brands = set()
        for name in brands:
            for word in _WORD.findall((name or "").lower()):
                if word not in self.domain:
                    self.domain[word] = 3
                    if len(word) < 6:
                        self._short_brands.add(word)
        self.nicknames = [n for n in nicknames if " " not in n]
        self.english = english_words()
        ranked = [w for w, _ in self.english.most_common(25_000) if len(w) > 2]
        self._pool = sorted({w for w in (*self.domain, *ranked) if len(w) > 2 and w.isalpha()
                             and w not in self._short_brands})
        self._by_len: dict[int, list[str]] = {}
        for word in self._pool:
            self._by_len.setdefault(len(word), []).append(word)

    def known(self, word: str) -> bool:
        low = word.lower().strip("'")
        forms = {low, low.removesuffix("'s"), low.removesuffix("s"), low.removesuffix("es"),
                 low.replace("'", "")}
        return any(f in self.domain or f in self.english for f in forms)

    def best(self, word: str, careful: bool = False) -> str | None:
        low = word.lower()
        size = len(low)
        limit = 1 if size <= 7 else 2 if size <= 10 else 3
        if careful:                        # a capitalised word may be a name we do not hold
            limit = 0 if size < 6 else 1 if size < 8 else 2
        pool = [w for n in range(size - limit, size + limit + 1) for w in self._by_len.get(n, ())]
        hits = process.extract(low, pool, scorer=OSA.distance, score_cutoff=limit, limit=40)

        def rank(item) -> tuple:
            candidate, distance, _ = item
            domain = self.domain.get(candidate, 0)
            # distance first; a changed first letter is a rarer mistake; at equal distance the
            # graph's own words win over general English
            return (distance + (0.6 if candidate[0] != low[0] else 0)
                    + (0.4 if sorted(candidate) != sorted(low) else 0) - (0.5 if domain >= 10 else 0)
                    + (0.1 if len(candidate) < size else 0),
                    -domain, -self.english.get(candidate, 0))
        if not hits and 6 <= size <= 7 and not careful:
            # two mistakes in a shorter word: only between unchanged outer letters
            pool = [w for n in range(size - 2, size + 3) for w in self._by_len.get(n, ())
                    if w[0] == low[0] and w[-1] == low[-1] and self.domain.get(w, 0) >= 5]
            hits = process.extract(low, pool, scorer=OSA.distance, score_cutoff=2, limit=40)
        return min(hits, key=rank)[0] if hits else None

    def correct(self, message: str) -> tuple[str, list[tuple[str, str]]]:
        text, changes = fix_identifiers(message)
        for token in re.findall(r"\b[A-Za-z]+\d[A-Za-z]+\b", text):      # "log4shel"
            near = [n for n in self.nicknames if 0 < OSA.distance(token.lower(), n) <= 2]
            if near and token.lower() not in self.nicknames and len(near) == 1:
                text = text.replace(token, near[0])
                changes.append((token, near[0]))
        out, last = [], 0
        for index, match in enumerate(_WORD.finditer(text)):
            word = match.group(0)
            before, after = text[match.start() - 1:match.start()], text[match.end():match.end() + 1]
            always = _SHORT.get(word.lower())
            if not always and (len(word) < 4 or self.known(word)):
                continue
            if before.isdigit() or after.isdigit() or before in "._/\\@" and before or after == "@":
                continue                                    # part of an id, path, address, version
            if word.isupper() and len(word) <= 5:
                continue                                    # acronym
            if any(c.isupper() for c in word[1:]) and not word.isupper():
                continue                                    # CamelCase product name
            fixed = always or self.best(word, careful=word[0].isupper() and index > 0)
            if fixed and fixed != word.lower():
                out += [text[last:match.start()], fixed]
                last = match.end()
                changes.append((word, fixed))
        return "".join(out) + text[last:], changes


_SHORT = {"wat": "what", "hwo": "how", "teh": "the", "waht": "what", "wich": "which", "wht": "what",
          "adn": "and", "taht": "that", "thier": "their", "wut": "what", "whta": "what", "haked": "hacked", "hakd": "hacked", "haker": "hacker", "fone": "phone",
          "helo": "hello", "authentification": "authentication"}
