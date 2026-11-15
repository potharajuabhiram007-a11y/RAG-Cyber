"""Query classification, graph / vector retrieval and evidence validation.

Decision order (the final decision is made here, *before* any generation):

1. identifier recognition  - CVE / CWE / CAPEC / ATT&CK ids -> exact lookup and
   Cypher traversal of the knowledge graph;
2. general communication   - greetings, thanks, farewells;
3. domain classification   - glossary-term matching against the foundational
   collection, dataset intent, a cybersecurity vocabulary, entity-name and
   vector search;
4. evidence validation     - a candidate is only accepted when the question's
   content words are actually covered by the retrieved evidence.

Outcomes: ``found`` (answer from evidence), ``not_found`` (supported domain but
insufficient evidence), ``unsupported`` (outside the domain) or ``general``.
The last three never reach the LLM.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Sequence

from backend.config import (
    CATEGORY_ATTACK, CATEGORY_CAPEC, CATEGORY_CVE, CATEGORY_CWE, CATEGORY_FUNDAMENTALS,
    CATEGORY_GENERAL, CATEGORY_UNSUPPORTED, SOURCE_NAMES, Settings,
)
from backend.database import (
    LABEL_ATTACK, LABEL_CAPEC, LABEL_CVE, LABEL_CWE, LABEL_DOC, LABEL_TERM, REL_CAN_PRECEDE,
    REL_CAPEC_ATTACK, REL_CAPEC_CHILD, REL_CVE_CWE, REL_CWE_CAPEC, REL_CWE_CHILD,
    REL_SUBTECHNIQUE_OF, Hop,
)
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import EmbeddingClient, clean_text, phrase_tokens

log = logging.getLogger(__name__)

STATUS_FOUND, STATUS_NOT_FOUND = "found", "not_found"
STATUS_UNSUPPORTED, STATUS_GENERAL = "unsupported", "general"

# --------------------------------------------------------------------------- #
# Identifier recognition
# --------------------------------------------------------------------------- #
_ID_PATTERNS = (
    (LABEL_CVE, re.compile(r"\bCVE[-\s_]?(\d{4})[-\s_]?(\d{4,7})\b", re.I),
     lambda m: f"CVE-{m.group(1)}-{m.group(2)}"),
    (LABEL_CWE, re.compile(r"\bCWE[-\s_:]{0,2}(\d{1,5})\b", re.I),
     lambda m: f"CWE-{int(m.group(1))}"),
    (LABEL_CAPEC, re.compile(r"\bCAPEC[-\s_:]{0,2}(\d{1,5})\b", re.I),
     lambda m: f"CAPEC-{int(m.group(1))}"),
    (LABEL_ATTACK, re.compile(r"\bT(\d{4})(?:[./](\d{3}))?\b", re.I),
     lambda m: f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")),
)


def extract_identifiers(message: str) -> list[tuple[str, str]]:
    """Ordered, de-duplicated (label, id) pairs mentioned in the message."""
    found: list[tuple[int, str, str]] = []
    for label, pattern, build in _ID_PATTERNS:
        for match in pattern.finditer(message):
            found.append((match.start(), label, build(match)))
    seen, ordered = set(), []
    for _, label, identifier in sorted(found):
        if identifier not in seen:
            seen.add(identifier)
            ordered.append((label, identifier))
    return ordered


# --------------------------------------------------------------------------- #
# General communication
# --------------------------------------------------------------------------- #
_GENERAL_PHRASES: tuple[tuple[str, str], ...] = tuple(sorted((
    ("how are you doing", "wellbeing"), ("how are you", "wellbeing"), ("how r u", "wellbeing"),
    ("how is it going", "wellbeing"), ("hows it going", "wellbeing"), ("how do you do", "wellbeing"),
    ("whats up", "wellbeing"), ("what is up", "wellbeing"), ("how are things", "wellbeing"),
    ("good morning", "greeting"), ("good afternoon", "greeting"), ("good evening", "greeting"),
    ("good day", "greeting"), ("hello", "greeting"), ("hi", "greeting"), ("hey", "greeting"),
    ("hiya", "greeting"), ("howdy", "greeting"), ("greetings", "greeting"), ("namaste", "greeting"),
    ("thank you so much", "thanks"), ("thank you very much", "thanks"), ("thank you", "thanks"),
    ("thanks a lot", "thanks"), ("many thanks", "thanks"), ("thanks", "thanks"), ("thx", "thanks"),
    ("much appreciated", "thanks"), ("appreciate it", "thanks"),
    ("goodbye", "farewell"), ("good bye", "farewell"), ("bye bye", "farewell"), ("bye", "farewell"),
    ("see you later", "farewell"), ("see you", "farewell"), ("take care", "farewell"),
    ("good night", "farewell"), ("have a nice day", "farewell"), ("have a good day", "farewell"),
    ("who are you", "identity"), ("what are you", "identity"), ("what can you do", "identity"),
    ("what do you do", "identity"), ("what is your name", "identity"),
    ("how can you help", "identity"), ("help me", "identity"), ("help", "identity"),
    ("okay", "acknowledgement"), ("ok", "acknowledgement"), ("alright", "acknowledgement"),
    ("got it", "acknowledgement"), ("i see", "acknowledgement"), ("great", "acknowledgement"),
    ("cool", "acknowledgement"), ("nice", "acknowledgement"), ("awesome", "acknowledgement"),
), key=lambda item: -len(item[0])))
_GENERAL_FILLERS = frozenset(
    "there rag cyber ragcyber assistant bot buddy friend sir madam mam team everyone all dear "
    "and for your the that it was is very so much a lot you today again really im i am fine "
    "doing well please just to me this helpful hope".split())


def detect_general(message: str) -> list[str]:
    """Kinds of small talk found, or [] when the message has other content."""
    text = " ".join(re.sub(r"[^a-z0-9\s]", "", message.lower().replace("'", "")).split())
    if not text or len(text.split()) > 14:
        return []
    kinds: list[str] = []
    padded = f" {text} "
    for phrase, kind in _GENERAL_PHRASES:
        needle = f" {phrase} "
        if needle in padded:
            padded = padded.replace(needle, "  ")
            if kind not in kinds:
                kinds.append(kind)
    leftovers = [tok for tok in padded.split() if tok not in _GENERAL_FILLERS]
    return kinds if kinds and not leftovers else []


# --------------------------------------------------------------------------- #
# Domain vocabulary and question analysis
# --------------------------------------------------------------------------- #
QUESTION_STOPWORDS = frozenset("""
a about all also am an and any are as at be been being between briefly but by can could
define definition describe detail details did difference differences different do does each
etc explain explanation for form from full give had has have how i if in into is it its
kind kinds know let like list many may me mean meaning means might more most much must my
name need no not of on one or our out overview please purpose role s shall short should
show simple simply so some stand stands tell than that the their them then there these
they this those to us use used uses using versus vs want was we were what when where
which who whom why will with work works would you your exactly basically actually really
compare comparison called known example examples type types
describes covers cover covering means refer refers relate relates named applies apply deals deal
""".split())

DOMAIN_VOCABULARY = frozenset("""
cyber cybersecurity security secure insecure network networks networking internet hacker
hackers hacking hack attack attacks attacker attackers malware virus viruses password
passwords encryption encrypt encrypted decrypt decryption cryptography cryptographic
vulnerability vulnerabilities exploit exploits exploitation threat threats firewall
firewalls router routers routing switch switches protocol protocols packet packets server
servers breach breaches phishing authentication authorization intrusion mitre nvd cve cves
cwe cwes capec cvss weakness weaknesses mitigation mitigations ransomware botnet trojan
spyware ddos dos wifi ethernet ip tcp udp dns dhcp subnet subnetting cipher hash hashing
certificate certificates infosec pentest pentesting forensics endpoint backdoor rootkit
spoofing sniffing payload vpn proxy lan wan osi topology topologies bandwidth injection
xss csrf att&ck adversary adversarial technique techniques tactic tactics credential
credentials privilege privileges http https ssh ftp tls ssl ipv4 ipv6 port ports
""".split())

_DATASET_WORDS = frozenset("""
cve cves cwe cwes capec capecs mitre att&ck attack attacks pattern patterns technique
techniques tactic tactics weakness weaknesses vulnerability vulnerabilities related
relationship relationships associated linked mapped mitigation mitigations find possible
subtechnique sub
""".split())

_INTENT_PATTERNS = (
    (LABEL_CVE, re.compile(r"\bcves?\b", re.I)),
    (LABEL_CWE, re.compile(r"\bcwes?\b|\bweakness(es)?\b", re.I)),
    (LABEL_CAPEC, re.compile(r"\bcapecs?\b|\battack\s+patterns?\b", re.I)),
    (LABEL_ATTACK, re.compile(r"att&ck|\b(sub-?)?techniques?\b|\btactics?\b|\bmitre\s+attack\b", re.I)),
)
_STRONG_INTENT_RE = re.compile(
    r"\b(which|list|find|show|related|associated|linked|mapped|against|exploit\w*|mitigat\w*)\b", re.I)
_COUNT_RE = re.compile(r"\bhow many\b|\bnumber of\b|\bcount of\b|\btotal number\b", re.I)
# Short acronyms that are also everyday English words: only matched when the
# user writes them in capitals or asks about nothing else.
_AMBIGUOUS_ALIASES = frozenset({"can", "man", "pan", "san", "mac", "apt", "dos", "ca", "soc",
                                "nat", "ap", "ss", "it", "salt", "bus", "ring", "star", "tree",
                                "mesh", "half", "full", "red", "blue", "purple", "hybrid"})


# --------------------------------------------------------------------------- #
# Vulnerability questions asked without a CVE identifier
# --------------------------------------------------------------------------- #
_CVE_QUESTION_RE = re.compile(
    r"\b(vulnerabilit\w+|flaws?|bugs?|cves?|security\s+(issue|hole)s?|zero[-\s]?days?)\b", re.I)
# Words that mark a vulnerability question without saying which vulnerability.
_CVE_GENERIC = frozenset("""
vulnerability vulnerabilities vulnerable flaw flaws bug bugs issue issues cve cves security
attacker attackers attack attacks allow allows allowing allowed cause causes caused causing
lead leads result results affect affects affected affecting os operating system systems
software product products version versions application applications program programs exist
exists found find related via user users certain possible possibly happen happens occur
occurs let lets make makes impact exploit exploits exploited exploitation zero day days
""".split())
_CVE_BOOST = frozenset({"remote", "remotely", "local", "locally", "authenticated",
                        "unauthenticated", "crash"})
# Wordings users type -> the wordings NVD descriptions use for the same thing.
_CVE_CONCEPTS: tuple[tuple[re.Pattern, tuple[str, ...]], ...] = tuple(
    (re.compile(pattern, re.I), alternatives) for pattern, alternatives in (
        (r"\bddos\b|\bdistributed\s+denial[-\s]of[-\s]service\b",
         ("distributed denial of service", "ddos")),
        (r"\bdos\b|\bdenial[-\s]of[-\s]service\b", ("denial of service",)),
        (r"\brce\b|\bremote\s+code\s+execution\b|\b(arbitrary\s+)?code\s+execution\b"
         r"|\bexecut\w+\s+(arbitrary\s+)?code\b",
         ("remote code execution", "execute arbitrary code", "arbitrary code execution",
          "execute code", "code execution")),
        (r"\bxss\b|\bcross[-\s]site\s+scripting\b", ("cross site scripting", "xss")),
        (r"\bcsrf\b|\bcross[-\s]site\s+request\s+forgery\b", ("cross site request forgery", "csrf")),
        (r"\bssrf\b|\bserver[-\s]side\s+request\s+forgery\b", ("server side request forgery", "ssrf")),
        (r"\bsqli\b|\bsql\s+injections?\b", ("sql injection",)),
        (r"\bcommand\s+injections?\b", ("command injection", "execute arbitrary commands")),
        (r"\bprivesc\b|\bprivilege\s+escalation\b|\belevation\s+of\s+privileges?\b"
         r"|\b(gain|escalate|elevate)\w*\s+privileges?\b",
         ("privilege escalation", "elevation of privilege", "gain privileges",
          "elevate privileges", "escalate privileges", "gain root privileges")),
        (r"\bbuffer\s+over(flow|run)s?\b", ("buffer overflow", "buffer overflows", "buffer overrun")),
        (r"\b(directory|path)\s+traversal\b", ("directory traversal", "path traversal")),
        (r"\binformation\s+(disclosure|leak\w*)\b|\binfo\s+leak\w*\b",
         ("information disclosure", "sensitive information", "information leak")),
        (r"\bauth\w*\s+bypass\b|\bbypass\w*\s+authentication\b",
         ("authentication bypass", "bypass authentication")),
        (r"\buse[-\s]after[-\s]free\b", ("use after free",)),
        (r"\bmemory\s+corruption\b", ("memory corruption",)),
        (r"\bwindows\s+(nt|xp|vista|me|ce|server(\s+\d{4})?|\d{1,4})\b", ()),   # kept as a phrase
        (r"\bmac\s*os(\s+x)?\b", ("mac os", "macos")),
        (r"\binternet\s+explorer\b", ("internet explorer",)),
    ))


# Widely used names of single, well-known vulnerabilities.  This is public knowledge
# written down by hand (never produced by a model); a name is only used when the
# graph really contains the record it points to.
CVE_NICKNAMES = {
    "heartbleed": "CVE-2014-0160", "shellshock": "CVE-2014-6271", "log4shell": "CVE-2021-44228",
    "eternalblue": "CVE-2017-0144", "bluekeep": "CVE-2019-0708", "zerologon": "CVE-2020-1472",
    "printnightmare": "CVE-2021-34527", "dirty cow": "CVE-2016-5195", "dirtycow": "CVE-2016-5195",
    "dirty pipe": "CVE-2022-0847", "spring4shell": "CVE-2022-22965", "poodle": "CVE-2014-3566",
    "sigred": "CVE-2020-1350", "baron samedit": "CVE-2021-3156", "proxylogon": "CVE-2021-26855",
    "smbghost": "CVE-2020-0796", "follina": "CVE-2022-30190",
}


def find_nickname(message: str) -> tuple[str, str] | None:
    text = " " + " ".join(re.findall(r"[a-z0-9]+", message.lower())) + " "
    for name, identifier in CVE_NICKNAMES.items():
        if f" {name} " in text:
            return name, identifier
    return None


def cve_search_terms(message: str) -> tuple[list[list[str]], list[str]]:
    """(required groups, ranking-only words) for a CVE description search.

    Every group must be present in a description; a group is a list of equivalent
    wordings.  Question words and generic vulnerability words are dropped.
    """
    text = " ".join(message.lower().split())
    groups: list[list[str]] = []
    for pattern, alternatives in _CVE_CONCEPTS:
        match = pattern.search(text)
        if not match:
            continue
        groups.append(list(alternatives) or [match.group(0)])
        text = pattern.sub(" ", text)
    boost: list[str] = []
    for token in re.findall(r"[a-z0-9]+(?:\.[0-9]+)*", text):
        if token in QUESTION_STOPWORDS or token in _CVE_GENERIC or len(token) < 2:
            continue
        if token in _CVE_BOOST:
            boost.append(token)
        elif [token] not in [g[:1] for g in groups]:
            groups.append([token] + ([stem(token)] if stem(token) != token else []))
    return groups, boost


def stem(token: str) -> str:
    """Very light plural stripping, applied identically to queries and aliases."""
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 4 and token.endswith(("ses", "xes", "ches", "shes")):
        return token[:-2]
    if len(token) > 4 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def content_tokens(tokens: Sequence[str]) -> list[str]:
    return [t for t in tokens if t not in QUESTION_STOPWORDS and (len(t) > 1 or t.isdigit())]


# --------------------------------------------------------------------------- #
# Result structures
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    kind: str                       # entity | term | document | statistic
    source: str
    text: str
    identifier: str | None = None
    title: str | None = None
    score: float | None = None
    page_number: int | None = None
    url: str | None = None


@dataclass
class RelatedGroup:
    relation: str                   # human readable, e.g. "Weaknesses (CVE_CWE)"
    label: str
    rel_type: str
    direction: str                  # direction of the last hop seen from the previous node
    chain: bool                     # part of the CVE->CWE->CAPEC->ATT&CK chain
    nodes: list[dict] = field(default_factory=list)
    total: int = 0

    def shown(self, limit: int | None = None) -> list[dict]:
        """Nodes to display.  For multi-hop results the selection rotates over the
        intermediate nodes, so every linked CWE / CAPEC is represented instead of
        the first one filling the whole list."""
        limit = limit or DISPLAY_LIMIT
        if len(self.nodes) <= limit:
            return list(self.nodes)
        buckets: dict[str, list[dict]] = {}
        for node in self.nodes:
            buckets.setdefault((node.get("via") or [""])[0], []).append(node)
        picked: list[dict] = []
        while len(picked) < limit and any(buckets.values()):
            for key in list(buckets):
                if buckets[key] and len(picked) < limit:
                    candidate = buckets[key].pop(0)
                    if candidate not in picked:
                        picked.append(candidate)
        return picked


@dataclass
class EntityContext:
    label: str
    node: dict
    groups: list[RelatedGroup] = field(default_factory=list)

    @property
    def related_ids(self) -> set[str]:
        return {n["id"] for g in self.groups for n in g.nodes}


@dataclass
class QueryAnalysis:
    message: str
    identifiers: list[tuple[str, str]]
    general_kinds: list[str]
    tokens: list[str]
    content: list[str]
    intent_labels: list[str]
    strong_intent: bool
    is_count: bool


@dataclass
class RetrievalResult:
    status: str
    category: str
    supported: bool
    analysis: QueryAnalysis
    general_kinds: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    contexts: list[EntityContext] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    relationships: list[tuple[str, str, str]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    statistics: dict | None = None
    reason: str = ""
    note: str = ""                  # how the evidence was selected, shown above the answer
    skip_llm: bool = False          # a failed lookup of something specific: never ask a model

    @property
    def found(self) -> bool:
        return self.status == STATUS_FOUND


# Traversals offered for each entity type: (relation text, hops, chain?)
_L = {LABEL_CVE: CATEGORY_CVE, LABEL_CWE: CATEGORY_CWE, LABEL_CAPEC: CATEGORY_CAPEC,
      LABEL_ATTACK: CATEGORY_ATTACK}
TRAVERSALS: dict[str, tuple[tuple[str, tuple[Hop, ...], bool], ...]] = {
    LABEL_CVE: (
        ("Weaknesses (CVE_CWE)", ((REL_CVE_CWE, "out", LABEL_CWE),), True),
        ("Attack patterns (CVE_CWE -> CWE_CAPEC)",
         ((REL_CVE_CWE, "out", LABEL_CWE), (REL_CWE_CAPEC, "out", LABEL_CAPEC)), True),
        ("ATT&CK techniques (CVE_CWE -> CWE_CAPEC -> CAPEC_ATTACK)",
         ((REL_CVE_CWE, "out", LABEL_CWE), (REL_CWE_CAPEC, "out", LABEL_CAPEC),
          (REL_CAPEC_ATTACK, "out", LABEL_ATTACK)), True),
    ),
    LABEL_CWE: (
        ("Parent weaknesses (CWE_CHILD)", ((REL_CWE_CHILD, "out", LABEL_CWE),), False),
        ("Child weaknesses (CWE_CHILD)", ((REL_CWE_CHILD, "in", LABEL_CWE),), False),
        ("Attack patterns (CWE_CAPEC)", ((REL_CWE_CAPEC, "out", LABEL_CAPEC),), True),
        ("ATT&CK techniques (CWE_CAPEC -> CAPEC_ATTACK)",
         ((REL_CWE_CAPEC, "out", LABEL_CAPEC), (REL_CAPEC_ATTACK, "out", LABEL_ATTACK)), True),
        ("Example vulnerabilities (CVE_CWE)", ((REL_CVE_CWE, "in", LABEL_CVE),), False),
    ),
    LABEL_CAPEC: (
        ("Exploited weaknesses (CWE_CAPEC)", ((REL_CWE_CAPEC, "in", LABEL_CWE),), True),
        ("ATT&CK techniques (CAPEC_ATTACK)", ((REL_CAPEC_ATTACK, "out", LABEL_ATTACK),), True),
        ("Parent attack patterns (CAPEC_CHILD)", ((REL_CAPEC_CHILD, "out", LABEL_CAPEC),), False),
        ("Child attack patterns (CAPEC_CHILD)", ((REL_CAPEC_CHILD, "in", LABEL_CAPEC),), False),
        ("Can precede (CAN_PRECEDE)", ((REL_CAN_PRECEDE, "out", LABEL_CAPEC),), False),
        ("Can follow (CAN_PRECEDE)", ((REL_CAN_PRECEDE, "in", LABEL_CAPEC),), False),
    ),
    LABEL_ATTACK: (
        ("Parent technique (SUBTECHNIQUE_OF)", ((REL_SUBTECHNIQUE_OF, "out", LABEL_ATTACK),), False),
        ("Sub-techniques (SUBTECHNIQUE_OF)", ((REL_SUBTECHNIQUE_OF, "in", LABEL_ATTACK),), False),
        ("Attack patterns (CAPEC_ATTACK)", ((REL_CAPEC_ATTACK, "in", LABEL_CAPEC),), True),
        ("Weaknesses (CAPEC_ATTACK <- CWE_CAPEC)",
         ((REL_CAPEC_ATTACK, "in", LABEL_CAPEC), (REL_CWE_CAPEC, "in", LABEL_CWE)), True),
    ),
}
MAX_IDS_WITH_CONTEXT = 3
TRAVERSE_LIMIT = 200          # ids kept for relationship checks
DISPLAY_LIMIT = 12            # related nodes shown / passed to generation per group


class Lexicon:
    """Alias index over the foundational collection (terms + document sections)."""

    def __init__(self, terms: list[dict], sections: list[dict]):
        self.entries: dict[tuple[str, ...], list[tuple[str, dict]]] = {}
        self.max_len = 1
        self.sections = sections
        for row in sections:
            row["_title_stems"] = [
                {stem(t) for t in alias.split() if t not in QUESTION_STOPWORDS}
                for alias in row.get("aliases") or [] if len(alias.split()) > 1]
        for kind, rows in (("term", terms), ("document", sections)):
            for row in rows:
                for alias in row.get("aliases") or []:
                    key = tuple(stem(t) for t in alias.split())
                    if not key:
                        continue
                    self.entries.setdefault(key, []).append((kind, row))
                    self.max_len = max(self.max_len, len(key))

    def match(self, tokens: Sequence[str], upper_words: set[str], only_content: list[str]
              ) -> tuple[list[tuple[str, dict, int]], set[int]]:
        """Greedy longest-phrase matching.  Returns (matches, covered positions)."""
        stems = [stem(t) for t in tokens]
        matches: list[tuple[str, dict, int]] = []
        covered: set[int] = set()
        position = 0
        while position < len(stems):
            hit = 0
            for length in range(min(self.max_len, len(stems) - position), 0, -1):
                key = tuple(stems[position:position + length])
                entries = self.entries.get(key)
                if not entries:
                    continue
                if length == 1 and tokens[position] in _AMBIGUOUS_ALIASES:
                    if tokens[position] not in upper_words and only_content != [tokens[position]]:
                        continue
                if length == 1 and tokens[position] in QUESTION_STOPWORDS:
                    continue
                for kind, row in entries:
                    matches.append((kind, row, length))
                covered.update(range(position, position + length))
                hit = length
                break
            position += hit or 1
        return matches, covered


class Retriever:
    def __init__(self, db, embedder: EmbeddingClient, settings: Settings,
                 tuning: Tuning = DEFAULT_TUNING):
        self.db, self.embedder, self.settings, self.tuning = db, embedder, settings, tuning
        self._lexicon: Lexicon | None = None
        self._lexicon_version = ""
        self._lexicon_checked = 0.0

    # ------------------------------------------------------------------ #
    # Analysis
    # ------------------------------------------------------------------ #
    def analyze(self, message: str) -> QueryAnalysis:
        identifiers = extract_identifiers(message)
        tokens = phrase_tokens(message)
        intent = [label for label, pattern in _INTENT_PATTERNS if pattern.search(message)]
        return QueryAnalysis(
            message=message, identifiers=identifiers,
            general_kinds=[] if identifiers else detect_general(message),
            tokens=tokens, content=content_tokens(tokens), intent_labels=intent,
            strong_intent=bool(intent) and bool(_STRONG_INTENT_RE.search(message)),
            is_count=bool(_COUNT_RE.search(message)))

    def retrieve(self, message: str) -> RetrievalResult:
        analysis = self.analyze(message)
        if analysis.identifiers:
            return self._retrieve_by_identifier(analysis)
        if analysis.general_kinds:
            return RetrievalResult(STATUS_GENERAL, CATEGORY_GENERAL, True, analysis,
                                   general_kinds=analysis.general_kinds,
                                   reason="general communication")
        if not analysis.content:
            return RetrievalResult(STATUS_UNSUPPORTED, CATEGORY_UNSUPPORTED, False, analysis,
                                   reason="no recognisable subject")
        if analysis.is_count and analysis.intent_labels:
            return self._retrieve_statistics(analysis)
        return self._retrieve_semantic(analysis)

    # ------------------------------------------------------------------ #
    # 1. Identifier lookup + graph traversal
    # ------------------------------------------------------------------ #
    def entity_context(self, label: str, identifier: str) -> EntityContext | None:
        node = self.db.get_node(label, identifier)
        if node is None:
            return None
        context = EntityContext(label=label, node=node)
        for relation, hops, chain in TRAVERSALS[label]:
            if len(hops) > self.tuning.max_hops:
                continue
            result = self.db.traverse(label, identifier, hops, limit=self.tuning.traverse_limit)
            rel_type, direction, target = hops[-1]
            context.groups.append(RelatedGroup(
                relation=relation, label=target, rel_type=rel_type, direction=direction,
                chain=chain, nodes=result["nodes"], total=result["total"]))
        return context

    def _retrieve_by_identifier(self, analysis: QueryAnalysis) -> RetrievalResult:
        primary_label = analysis.identifiers[0][0]
        result = RetrievalResult(STATUS_NOT_FOUND, _L[primary_label], True, analysis,
                                 identifiers=[i for _, i in analysis.identifiers])
        absent: list[str] = []
        for label, identifier in analysis.identifiers:
            if len(result.contexts) >= MAX_IDS_WITH_CONTEXT:
                break
            context = self.entity_context(label, identifier)
            if context is None:
                absent.append(identifier)
            else:
                result.contexts.append(context)
        if not result.contexts:
            result.reason = "identifier(s) not present in the knowledge graph: " + ", ".join(absent)
            return result
        result.status = STATUS_FOUND
        result.category = _L[result.contexts[0].label]
        for identifier in absent:
            result.missing.append(f"{identifier} was not found in the knowledge graph.")
        for context in result.contexts:
            self._add_context(result, context)
        self._check_pairs(result)
        return result

    def _add_context(self, result: RetrievalResult, context: EntityContext) -> None:
        node, label = context.node, context.label
        result.evidence.append(Evidence(
            kind="entity", source=SOURCE_NAMES[_L[label]], identifier=node["id"],
            title=node.get("name") or node["id"], text=describe_entity(label, node),
            url=node.get("source_url")))
        self._collect_mitigations(result, label, node, limit=6)
        for group in context.groups:
            if not group.nodes:
                if group.chain:
                    target = {LABEL_CWE: "CWE weakness", LABEL_CAPEC: "CAPEC attack pattern",
                              LABEL_ATTACK: "ATT&CK technique"}.get(group.label, group.label)
                    result.missing.append(
                        f"No {target} relationship was found for {node['id']} in the current "
                        f"graph (path: {group.relation.split('(')[-1].rstrip(')')}).")
                continue
            for related in group.nodes:
                for via in related.get("via") or [node["id"]]:
                    edge = ((via, group.rel_type, related["id"]) if group.direction == "out"
                            else (related["id"], group.rel_type, via))
                    if edge not in result.relationships:
                        result.relationships.append(edge)
            shown = group.shown()
            lines = [f"{n['id']}: {n.get('name') or ''}"
                     + (f" (via {', '.join(n['via'])})" if n.get("via") and n["via"] != [node["id"]] else "")
                     + (f" - {clean_text(n.get('description'), 220)}" if index < 4 and group.label != LABEL_CVE
                        and n.get("description") else "")
                     for index, n in enumerate(shown)]
            more = f" (showing {len(shown)} of {group.total})" if group.total > len(shown) else ""
            result.evidence.append(Evidence(
                kind="entity", source=SOURCE_NAMES[_L[group.label]],
                identifier=", ".join(n["id"] for n in shown[:6]) + (" ..." if len(shown) > 6 else ""),
                title=f"{group.relation} for {node['id']}{more}", text="\n".join(lines)))
            if group.chain:
                for related in shown[:3]:
                    self._collect_mitigations(result, group.label, related, limit=2)

    @staticmethod
    def _collect_mitigations(result: RetrievalResult, label: str, node: dict, limit: int) -> None:
        for text in (node.get("mitigations") or [])[:limit]:
            entry = f"[{node['id']}] {clean_text(text, 600)}"
            if entry not in result.mitigations and len(result.mitigations) < 14:
                result.mitigations.append(entry)
        if label == LABEL_CVE:
            for url in (node.get("patch_urls") or [])[:4]:
                entry = f"[{node['id']}] Vendor advisory / patch reference listed by NVD: {url}"
                if entry not in result.mitigations:
                    result.mitigations.append(entry)

    @staticmethod
    def _check_pairs(result: RetrievalResult) -> None:
        """State explicitly whether the mentioned entities are connected."""
        contexts = result.contexts
        for i, first in enumerate(contexts):
            for second in contexts[i + 1:]:
                a, b = first.node["id"], second.node["id"]
                if b in first.related_ids or a in second.related_ids:
                    continue
                result.missing.append(
                    f"No relationship between {a} and {b} was found in the current graph.")

    # ------------------------------------------------------------------ #
    # 2. Graph statistics ("How many CVEs are there?")
    # ------------------------------------------------------------------ #
    def _retrieve_statistics(self, analysis: QueryAnalysis) -> RetrievalResult:
        counts = self.db.counts()
        label = analysis.intent_labels[0]
        result = RetrievalResult(STATUS_FOUND, _L[label], True, analysis, statistics=counts)
        if not counts["nodes"].get(label):
            result.status, result.reason = STATUS_NOT_FOUND, f"no {label} nodes are stored yet"
            return result
        node_lines = [f"{name} nodes: {counts['nodes'].get(name, 0)}"
                      for name in (LABEL_CVE, LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK)]
        rel_lines = [f"{name} relationships: {value}" for name, value in counts["relationships"].items()]
        result.evidence.append(Evidence(
            kind="statistic", source="RAG-Cyber Neo4j knowledge graph", title="Current graph statistics",
            text="\n".join(node_lines + rel_lines)))
        return result

    # ------------------------------------------------------------------ #
    # 3. Semantic retrieval (fundamentals first, then the four datasets)
    # ------------------------------------------------------------------ #
    def _get_lexicon(self) -> Lexicon:
        now = time.monotonic()
        if self._lexicon is None or now - self._lexicon_checked > 60:
            version = self.db.foundation_version()
            if self._lexicon is None or version != self._lexicon_version:
                self._lexicon = Lexicon(self.db.list_terms(), self.db.list_document_sections())
                self._lexicon_version = version
            self._lexicon_checked = now
        return self._lexicon

    def _query_vector(self, analysis: QueryAnalysis) -> list[float] | None:
        try:
            return self.embedder.embed_one(analysis.message)
        except Exception as exc:
            log.warning("Query embedding failed (%s); continuing without vector search",
                        type(exc).__name__)
            return None

    def _retrieve_semantic(self, analysis: QueryAnalysis) -> RetrievalResult:
        tokens, content = analysis.tokens, analysis.content
        upper_words = {w.lower() for w in re.findall(r"\b(?=\w*[A-Z]\w*[A-Z])[A-Za-z0-9&]+\b", analysis.message)}
        matches, covered = self._get_lexicon().match(tokens, upper_words, content)
        content_positions = [i for i, t in enumerate(tokens) if t in content]
        term_coverage = (sum(1 for i in content_positions if i in covered) / len(content_positions)
                         if content_positions else 0.0)
        domain_hits = [t for i, t in enumerate(tokens)
                       if t in content and (i in covered or t in DOMAIN_VOCABULARY
                                            or stem(t) in DOMAIN_VOCABULARY)]
        vector = self._query_vector(analysis)

        nickname = find_nickname(analysis.message)
        if nickname:
            named = self._cve_by_nickname(analysis, *nickname)
            if named is not None:
                return named

        # "the vulnerability that lets a remote attacker crash Windows NT": a CVE is
        # being described rather than named, so the CVE descriptions are searched.
        # A word the glossary does not know (usually a product name) next to a
        # vulnerability word or an impact ("buffer overflow in Apache Tomcat") means the
        # question is about specific records, not about the concept itself.
        other_dataset = any(label != LABEL_CVE for label in analysis.intent_labels)
        cve_question = bool(_CVE_QUESTION_RE.search(analysis.message)) and not other_dataset
        groups = cve_search_terms(analysis.message)[0]
        known = {tokens[i] for i in covered} | DOMAIN_VOCABULARY
        specific = any(" " not in g[0] and g[0] not in known and stem(g[0]) not in known
                       for g in groups)
        impact_and_product = specific and not other_dataset and any(" " in g[0] for g in groups)
        described_tried = False
        if cve_question or impact_and_product:
            if specific or not (matches and term_coverage >= 0.5):
                described_tried = True
                described = self._cve_description_search(
                    analysis, min_groups=1 if cve_question else 2)
                if described is None and cve_question and specific:
                    # A vulnerability in a named product was asked for and no record
                    # describes it: defining the general terms instead would mislead.
                    return RetrievalResult(
                        STATUS_NOT_FOUND, CATEGORY_CVE, True, analysis, skip_llm=True,
                        reason="no CVE description matches the described vulnerability")
                if described is not None:
                    return described

        if matches and term_coverage >= 0.5 and not analysis.strong_intent:
            return self._fundamentals_result(analysis, matches, vector)

        if cve_question and not described_tried:
            described = self._cve_description_search(analysis, min_groups=1)
            if described is not None:
                return described

        if analysis.intent_labels or not matches:
            entity = self._entity_search(analysis, vector)
            if entity is not None:
                return entity

        if matches and term_coverage >= 0.5:
            return self._fundamentals_result(analysis, matches, vector)

        semantic = self._fundamentals_semantic(analysis, vector)
        if semantic is not None:
            return semantic

        if (not described_tried and not cve_question and not other_dataset
                and (domain_hits or analysis.intent_labels)):
            described = self._cve_description_search(analysis, min_groups=2)
            if described is not None:
                return described

        if domain_hits or analysis.intent_labels:
            category = _L[analysis.intent_labels[0]] if analysis.intent_labels else CATEGORY_FUNDAMENTALS
            return RetrievalResult(STATUS_NOT_FOUND, category, True, analysis,
                                   skip_llm=bool(analysis.intent_labels),
                                   reason="cybersecurity question without sufficient evidence")
        return RetrievalResult(STATUS_UNSUPPORTED, CATEGORY_UNSUPPORTED, False, analysis,
                               reason="outside the supported knowledge categories")

    # -- fundamentals ---------------------------------------------------- #
    def _fundamentals_result(self, analysis: QueryAnalysis, matches, vector) -> RetrievalResult:
        result = RetrievalResult(STATUS_FOUND, CATEGORY_FUNDAMENTALS, True, analysis)
        seen: set[str] = set()
        for kind, row, length in sorted(matches, key=lambda m: (-m[2], m[0] != "term")):
            if row["id"] in seen or len(result.evidence) >= 8:
                continue
            seen.add(row["id"])
            result.evidence.append(_foundation_evidence(kind, row, score=None))
        # Reference sections whose whole title is covered by the question
        # (e.g. "TCP vs UDP" for "difference between TCP and UDP").
        wanted = {stem(t) for t in analysis.content}
        for section in self._get_lexicon().sections:
            if section["id"] not in seen and len(result.evidence) < 10 and any(
                    title and title <= wanted for title in section["_title_stems"]):
                seen.add(section["id"])
                result.evidence.append(_foundation_evidence("document", section, score=None))
        return result

    def _fundamentals_semantic(self, analysis: QueryAnalysis, vector) -> RetrievalResult | None:
        accepted: list[Evidence] = []
        for label, kind, text_key in ((LABEL_TERM, "term", "definition"), (LABEL_DOC, "document", "content")):
            for hit in self._vector_hits(label, vector, self.tuning.vector_k):
                text = f"{hit.get('term') or hit.get('section') or ''} {hit.get(text_key, '')}"
                if (self._text_coverage(analysis.content, text) >= self.tuning.fundamentals_coverage
                        and len(accepted) < 5):
                    accepted.append(_foundation_evidence(kind, hit, hit["_score"]))
        if not accepted:
            return None
        return RetrievalResult(STATUS_FOUND, CATEGORY_FUNDAMENTALS, True, analysis, evidence=accepted)

    def _vector_hits(self, label: str, vector, k: int) -> list[dict]:
        if not vector:
            return []
        floor = (self.tuning.vector_min_score if self.tuning.vector_min_score is not None
                 else self.settings.effective_vector_min_score)
        return [hit for hit in self.db.vector_search(label, vector, k) if hit["_score"] >= floor]

    @staticmethod
    def _text_coverage(content: Sequence[str], text: str) -> float:
        """Share of the question's content words that occur in the evidence text."""
        if not content:
            return 0.0
        available = {stem(t) for t in phrase_tokens(text)}
        return sum(1 for t in content if stem(t) in available) / len(content)

    # -- a CVE known by its nickname --------------------------------------- #
    def _cve_by_nickname(self, analysis: QueryAnalysis, name: str, identifier: str
                         ) -> RetrievalResult | None:
        context = self.entity_context(LABEL_CVE, identifier)
        if context is None:
            return None
        result = RetrievalResult(STATUS_FOUND, CATEGORY_CVE, True, analysis,
                                 identifiers=[identifier], contexts=[context])
        self._add_context(result, context)
        result.note = (f'No CVE identifier was given. "{name.title()}" is the widely used name of '
                       f"{identifier} (matched from a built-in list of well-known vulnerability names "
                       "and checked against the knowledge graph).")
        return result

    # -- a CVE described in words ------------------------------------------ #
    def _cve_description_search(self, analysis: QueryAnalysis, min_groups: int
                                ) -> RetrievalResult | None:
        groups, boost = cve_search_terms(analysis.message)
        if not min_groups <= len(groups) <= 10:
            return None
        found = self.db.cve_text_search(groups, boost, k=self.tuning.cve_pool_k)
        dropped: list[str] = []
        if not found["nodes"] and len(groups) >= 3:
            # One word of the question may simply not be in any description
            # ("server", "machine"...): retry leaving out one plain word at a time.
            for index, group in enumerate(groups):
                if index >= 6:
                    continue
                found = self.db.cve_text_search(groups[:index] + groups[index + 1:], boost,
                                                k=self.tuning.cve_pool_k)
                if found["nodes"]:
                    dropped, groups = [group[0]], groups[:index] + groups[index + 1:]
                    break
        if not found["nodes"]:
            return None
        # Every candidate already contains all required terms; order them by how much
        # of the question's own wording ("remote", "attackers", "allows"...) they share.
        wanted = {stem(t) for t in analysis.content}

        def closeness(node: dict) -> tuple:
            words = {stem(t) for t in phrase_tokens(node.get("description") or "")}
            return (-len(wanted & words), -node.get("_score", 0.0))

        nodes = sorted(found["nodes"], key=closeness)[:self.tuning.cve_result_k]
        context = self.entity_context(LABEL_CVE, nodes[0]["id"])
        if context is None:
            return None
        result = RetrievalResult(STATUS_FOUND, CATEGORY_CVE, True, analysis,
                                 identifiers=[nodes[0]["id"]], contexts=[context])
        self._add_context(result, context)
        for other in nodes[1:]:
            result.identifiers.append(other["id"])
            result.evidence.append(Evidence(
                kind="entity", source=SOURCE_NAMES[CATEGORY_CVE], identifier=other["id"],
                title=clean_text(other.get("description") or other["id"], 260),
                text=describe_entity(LABEL_CVE, other), score=other.get("_score"),
                url=other.get("source_url")))
        total = found["total"]
        wording = ", ".join(f'"{group[0]}"' for group in groups)
        count = "1,000 or more CVE records" if total >= 1000 else (
            f"{total} CVE records" if total != 1 else "1 CVE record")
        result.note = (f"No CVE identifier was given, so the CVE descriptions in the knowledge "
                       f"graph were searched for {wording}. {count} matched"
                       + ("; the closest match is described first." if total > 1 else "."))
        if dropped:
            result.note += f' No description also contained "{dropped[0]}", so it was left out.'
        return result

    # -- CWE / CAPEC / ATT&CK / CVE without an identifier ------------------ #
    def _entity_search(self, analysis: QueryAnalysis, vector) -> RetrievalResult | None:
        subject = [t for t in analysis.content if t not in _DATASET_WORDS]
        if not subject:
            return None
        labels = [l for l in analysis.intent_labels if l != LABEL_CVE] or [LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK]
        candidates: dict[str, dict] = {}
        tune = self.tuning
        for hit in self.db.name_search(" ".join(subject), labels, k=tune.name_search_k):
            candidates[hit["id"]] = hit
        for label in labels + ([LABEL_CVE] if LABEL_CVE in analysis.intent_labels else []):
            for hit in self._vector_hits(label, vector, tune.vector_k):
                if hit["id"] in candidates:
                    candidates[hit["id"]]["_vec"] = hit["_score"]
                else:
                    candidates[hit["id"]] = {**hit, "_vec": hit["_score"]}
        scored = []
        for hit in candidates.values():
            name_text = " ".join([hit.get("name") or ""] + list(hit.get("alternate_terms") or []))
            name_cov = self._text_coverage(subject, name_text)
            full_cov = self._text_coverage(subject, f"{name_text} {hit.get('description', '')}")
            if name_cov == 1.0 or (analysis.intent_labels and full_cov >= tune.entity_full_cov
                                   and hit["_label"] in (analysis.intent_labels or [])):
                words = len((hit.get("name") or "").split())
                if tune.rank_mode == "weighted":
                    value = (tune.w_name * name_cov + tune.w_vector * hit.get("_vec", 0.0)
                             + tune.w_desc * full_cov - tune.w_length * words)
                    scored.append((-value, 0, 0, hit))
                else:
                    # prefer complete name matches, then the shortest (most specific) name
                    scored.append((-name_cov, words, -hit.get("_score", 0), hit))
        if not scored:
            return None
        scored.sort(key=lambda item: item[:3])
        best = scored[0][3]
        context = self.entity_context(best["_label"], best["id"])
        if context is None:
            return None
        result = RetrievalResult(STATUS_FOUND, _L[best["_label"]], True, analysis,
                                 identifiers=[best["id"]], contexts=[context])
        self._add_context(result, context)
        for _, _, _, other in scored[1:1 + tune.extra_entries]:
            result.identifiers.append(other["id"])
            result.evidence.append(Evidence(
                kind="entity", source=SOURCE_NAMES[_L[other["_label"]]], identifier=other["id"],
                title=other.get("name"), text=describe_entity(other["_label"], other),
                score=other.get("_score"), url=other.get("source_url")))
        return result


# --------------------------------------------------------------------------- #
# Evidence text builders (embeddings are never included)
# --------------------------------------------------------------------------- #
def _foundation_evidence(kind: str, row: dict, score: float | None) -> Evidence:
    if kind == "term":
        text = f"{row.get('term')}: {row.get('definition')}"
        if row.get("category"):
            text += f" (Category: {row['category']})"
        return Evidence(kind="term", source=row.get("source") or "Foundational collection",
                        identifier=row.get("term"), title=row.get("term"), text=text, score=score,
                        page_number=row.get("page_number"))
    return Evidence(kind="document", source=row.get("source") or "Foundational collection",
                    identifier=row.get("section"), title=row.get("title"),
                    text=row.get("content", ""), score=score, page_number=row.get("page_number"))


def _join(values, limit: int = 12) -> str:
    values = list(values or [])
    return ", ".join(values[:limit]) + (f" (+{len(values) - limit} more)" if len(values) > limit else "")


def describe_entity(label: str, node: dict) -> str:
    """Readable fact sheet of one graph node, built only from stored properties."""
    lines = [f"{node['id']}" + (f" - {node['name']}" if node.get("name") and node["name"] != node["id"] else "")]
    if node.get("description"):
        lines.append(f"Description: {clean_text(node['description'], 1800)}")
    if label == LABEL_CVE:
        if node.get("base_score") is not None:
            lines.append(f"CVSS v{node.get('cvss_version') or '?'} base score: {node['base_score']}"
                         + (f" ({node['severity']})" if node.get("severity") else ""))
        else:
            lines.append("CVSS base score: not provided by NVD for this record")
        for key, text in (("exploitability_score", "Exploitability score"), ("impact_score", "Impact score")):
            lines.append(f"{text}: {node[key]}" if node.get(key) is not None
                         else f"{text}: not provided by NVD")
        for key, text in (("cvss_vector", "CVSS vector"), ("published", "Published"),
                          ("last_modified", "Last modified"), ("vuln_status", "NVD status")):
            if node.get(key):
                lines.append(f"{text}: {node[key]}")
        lines.append("CWE identifiers listed by NVD: " + (_join(node.get("related_cwe_ids")) or "none"))
        if node.get("affected_products"):
            lines.append("Affected products (vendor:product): " + _join(node["affected_products"]))
        if node.get("reference_urls"):
            lines.append("References: " + _join(node["reference_urls"], 5))
    elif label == LABEL_CWE:
        if node.get("alternate_terms"):
            lines.append("Also known as: " + _join(node["alternate_terms"]))
        for key, text in (("category", "Abstraction"), ("status", "Status"),
                          ("likelihood", "Likelihood of exploit")):
            if node.get(key):
                lines.append(f"{text}: {node[key]}")
        if node.get("extended_description"):
            lines.append(f"Details: {clean_text(node['extended_description'], 900)}")
        if node.get("consequences"):
            lines.append("Common consequences: " + "; ".join(node["consequences"][:6]))
    elif label == LABEL_CAPEC:
        for key, text in (("category", "Abstraction"), ("likelihood", "Likelihood of attack"),
                          ("severity", "Typical severity"), ("status", "Status")):
            if node.get(key):
                lines.append(f"{text}: {node[key]}")
        if node.get("prerequisites"):
            lines.append("Prerequisites: " + " | ".join(node["prerequisites"][:4]))
    elif label == LABEL_ATTACK:
        lines.append(f"Type: {node.get('type') or 'technique'}")
        lines.append("Tactic(s): " + (_join(node.get("tactics")) or node.get("category") or "not listed"))
        if node.get("platforms"):
            lines.append("Platforms: " + _join(node["platforms"]))
        if node.get("detection"):
            lines.append(f"Detection: {clean_text(node['detection'], 600)}")
    if node.get("mitigations"):
        lines.append("Mitigations: " + " | ".join(clean_text(m, 400) for m in node["mitigations"][:5]))
    if node.get("source_url"):
        lines.append(f"Source: {node['source_url']}")
    return "\n".join(lines)
