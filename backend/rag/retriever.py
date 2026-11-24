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

The sources are asked strictly in this order, and a later one only when the earlier ones
have no answer:

* ``graph``    - identifiers, record names, glossary terms, words of CVE descriptions and the
                 relationships of what was found; no embedding is computed;
* ``semantic`` - vector similarity over the embeddings of names and descriptions;
* ``other``    - loosely matching text, the live NVD, then (in the generator) the language
                 model's own knowledge.

Outcomes: ``found`` (answer from evidence), ``not_found`` (supported domain but
insufficient evidence), ``unsupported`` (outside the domain) or ``general``.
The last three never reach the LLM.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Sequence

from backend.config import (
    CATEGORY_ATTACK, CATEGORY_CAPEC, CATEGORY_CVE, CATEGORY_CWE, CATEGORY_FUNDAMENTALS,
    CATEGORY_GENERAL, CATEGORY_UNSUPPORTED, SOURCE_NAMES, Settings,
)
from backend.database import (
    LABEL_ATTACK, LABEL_CAPEC, LABEL_CVE, LABEL_CWE, LABEL_DOC, LABEL_MITIGATION, LABEL_PRODUCT,
    LABEL_TACTIC, LABEL_TERM, LABEL_VENDOR, REL_AFFECTS, REL_CAN_PRECEDE, REL_HAS_TACTIC,
    REL_MADE_BY, REL_MITIGATES,
    REL_CAPEC_ATTACK, REL_CAPEC_CHILD, REL_CVE_CWE, REL_CWE_CAPEC, REL_CWE_CHILD,
    REL_SUBTECHNIQUE_OF, Hop,
)
from backend.rag.external import NVDLookup
from backend.rag.spelling import SpellCorrector
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import EmbeddingClient, clean_text, phrase_tokens

log = logging.getLogger(__name__)

STATUS_FOUND, STATUS_NOT_FOUND = "found", "not_found"
STATUS_UNSUPPORTED, STATUS_GENERAL = "unsupported", "general"
GRAPH, SEMANTIC, OTHER = STEPS = ("graph", "semantic", "other")

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
    (LABEL_ATTACK, re.compile(r"\bT(\d{4})(?:[./](\d{3}))?\b(?![./]\d)", re.I),
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
            while needle in padded:
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
prevent prevented preventing protect protecting defend against avoid stop fix
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
# Threat mapping: an incident described in everyday words ("my phone is hacked"),
# or a question about how things relate that names no identifier ("which weaknesses
# lead to SQL injection?"). The description is matched by meaning and by name against
# ATT&CK, CAPEC and CWE; every answer still comes only from records in the graph.
# --------------------------------------------------------------------------- #
_SCENARIO_RE = re.compile(
    r"\b(hack(ed|ing|er)?|compromis\w*|stole|stolen|steal\w*|infect\w*|virus\w*|malware|trojan\w*|"
    r"ransom\w*|spyware|adware|keylog\w*|phish\w*|smish\w*|scam\w*|fraud\w*|breach\w*|leak\w*|"
    r"spying|spied|tracked|tracking me|hijack\w*|taken over|takeover|locked out|pop-?ups?|"
    r"suspicious|unauthori[sz]ed|someone (got|logged|accessed|is)|strange (app|login|activity)|"
    r"encrypted my|attacked|being attacked|threat\w*|guess\w*|keeps? trying|trying to (log|get|access|break)|"
    r"broke into|break into|lost access|can'?t log ?in|weird (messages?|emails?|calls?)|impersonat\w*)\b", re.I)
_MAPPING_RE = re.compile(
    r"\b(type of|kind of|which|what)\b.{0,40}\b(cves?|cwes?|capecs?|att&ck|weakness(es)?|"
    r"vulnerabilit\w+|attack(s| patterns?)?|techniques?|threats?)\b"
    r"|\b(lead(s)? to|led to|cause[sd]?|behind|used (in|for|by)|related to|linked to|"
    r"associated with|mapped to|exploited (in|by))\b", re.I)
# everyday wording -> security terms used for the search (search words only)
_SCENARIO_HINTS = (
    (re.compile(r"\b(phone|mobile|android|iphone|ios|smartphone|tablet)\b", re.I),
     "mobile device malware spyware"),
    (re.compile(r"\b(hack(ed|ing)?|compromis\w*|taken over|takeover|someone (got|logged|accessed))\b", re.I),
     "unauthorized access account compromise valid accounts"),
    (re.compile(r"\b(fake (login|site|page|website|email|link|call)|phish\w*|smish\w*|vish\w*|spoof\w*|scam\w*|"
                r"text message|sms|whatsapp|(message|email|call|link)s? (asking|telling|saying|from)|"
                r"asking for (my )?(password|details|otp|code|pin|bank|card)|bank details|clicked (a|on a) link)\b", re.I),
     "phishing spearphishing social engineering lure"),
    (re.compile(r"\b(passwords?|credentials?|login|logged in|account)\b", re.I),
     "credential theft account credentials"),
    (re.compile(r"\b(guess\w*|brute|many (attempts|tries)|keeps? trying|login attempts)\b", re.I),
     "brute force password guessing"),
    (re.compile(r"\b(pop-?ups?|ads|adware|slow|browser (redirect|hijack\w*))\b", re.I),
     "adware malicious software browser hijacking"),
    (re.compile(r"\b(ransom\w*|encrypted my|files? (are|were) (locked|encrypted))\b", re.I),
     "ransomware data encrypted for impact"),
    (re.compile(r"\b(wi-?fi|wireless|router|hotspot)\b", re.I),
     "wireless network rogue access point weak authentication"),
    (re.compile(r"\b(virus\w*|malware|infect\w*|trojan\w*|worm)\b", re.I),
     "malicious software code execution"),
    (re.compile(r"\b(spy\w*|camera|microphone|track(ed|ing)|location)\b", re.I),
     "spyware audio capture video capture location tracking"),
    (re.compile(r"\b(bank\w*|money|card|payment|financial)\b", re.I),
     "financial theft fraud"),
    (re.compile(r"\b(keylog\w*|keystrokes?)\b", re.I), "input capture keylogging"),
    (re.compile(r"\b(leak\w*|breach\w*|exfiltrat\w*|data (was|got) stolen)\b", re.I),
     "data exfiltration data from local system"),
    (re.compile(r"\b(website|web site|web app|site) (hacked|defaced|down)\b", re.I),
     "web application exploitation defacement"),
    (re.compile(r"\b(ddos|denial of service|website down|server down|flood\w*)\b", re.I),
     "denial of service network flood"),
)


def scenario_hints(message: str) -> str:
    return " ".join(hint for pattern, hint in _SCENARIO_HINTS if pattern.search(message))


# an incident is described by someone it happened to, not asked about in general
_PERSONAL_RE = re.compile(
    r"\b(my|me|our|us|someone|somebody|i'm|i've|"
    r"i (got|was|have|had|clicked|think|lost|received|downloaded|installed|opened|noticed|see|saw|am|keep|can'?t)|"
    r"we (got|were|have|had|are|lost)|(got|was|were|been|is|are) (hacked|compromised|infected|stolen|breached))\b", re.I)


def is_scenario(message: str) -> bool:
    return bool(_SCENARIO_RE.search(message) and _PERSONAL_RE.search(message))


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
        elif not any({token, stem(token)} & set(g) for g in groups):
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
        limit = DISPLAY_LIMIT if limit is None else max(0, limit)
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
class Question:
    """What the retrieval steps need to know about one question."""
    analysis: QueryAnalysis
    matches: list                   # glossary terms and sections named in the question
    term_coverage: float
    domain_hits: list[str]
    groups: list[list[str]]         # search terms for CVE descriptions
    other_dataset: bool
    cve_question: bool
    specific: bool                  # names something the glossary does not know (a product)
    impact_and_product: bool
    scenario: bool
    mapping: bool
    prevention: bool
    described_tried: bool = False
    named_miss: bool = False        # a named product's vulnerability that the graph does not describe
    _vector: list = field(default_factory=list)

    @property
    def defined(self) -> bool:
        return bool(self.matches) and self.term_coverage >= 0.5

    @property
    def mapped(self) -> bool:
        return self.scenario or self.mapping or self.prevention


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
    corrections: list[tuple[str, str]] = field(default_factory=list)   # (typed, understood as)
    features: dict = field(default_factory=dict)                       # for the confidence score
    note: str = ""                  # how the evidence was selected, shown above the answer
    method: str = "none"            # graph | semantic | other: the step that found the evidence
    tried: list[str] = field(default_factory=list)          # steps tried, in order
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
        ("Vulnerabilities (CVEs) with this weakness (reverse: CWE <- CVE_CWE <- CVE)",
         ((REL_CVE_CWE, "in", LABEL_CVE),), False),
    ),
    LABEL_CAPEC: (
        ("Exploited weaknesses (CWE_CAPEC)", ((REL_CWE_CAPEC, "in", LABEL_CWE),), True),
        ("ATT&CK techniques (CAPEC_ATTACK)", ((REL_CAPEC_ATTACK, "out", LABEL_ATTACK),), True),
        ("Parent attack patterns (CAPEC_CHILD)", ((REL_CAPEC_CHILD, "out", LABEL_CAPEC),), False),
        ("Child attack patterns (CAPEC_CHILD)", ((REL_CAPEC_CHILD, "in", LABEL_CAPEC),), False),
        ("Can precede (CAN_PRECEDE)", ((REL_CAN_PRECEDE, "out", LABEL_CAPEC),), False),
        ("Can follow (CAN_PRECEDE)", ((REL_CAN_PRECEDE, "in", LABEL_CAPEC),), False),
        ("Vulnerabilities (CVEs) open to this attack pattern "
         "(reverse: CAPEC <- CWE_CAPEC <- CWE <- CVE_CWE <- CVE)",
         ((REL_CWE_CAPEC, "in", LABEL_CWE), (REL_CVE_CWE, "in", LABEL_CVE)), False),
    ),
    LABEL_ATTACK: (
        ("Parent technique (SUBTECHNIQUE_OF)", ((REL_SUBTECHNIQUE_OF, "out", LABEL_ATTACK),), False),
        ("Sub-techniques (SUBTECHNIQUE_OF)", ((REL_SUBTECHNIQUE_OF, "in", LABEL_ATTACK),), False),
        ("Attack patterns (CAPEC_ATTACK)", ((REL_CAPEC_ATTACK, "in", LABEL_CAPEC),), True),
        ("Weaknesses (CAPEC_ATTACK <- CWE_CAPEC)",
         ((REL_CAPEC_ATTACK, "in", LABEL_CAPEC), (REL_CWE_CAPEC, "in", LABEL_CWE)), True),
        ("Vulnerabilities (CVEs) linked to this technique "
         "(reverse: ATT&CK <- CAPEC_ATTACK <- CAPEC <- CWE_CAPEC <- CWE <- CVE_CWE <- CVE)",
         ((REL_CAPEC_ATTACK, "in", LABEL_CAPEC), (REL_CWE_CAPEC, "in", LABEL_CWE),
          (REL_CVE_CWE, "in", LABEL_CVE)), False),
    ),
}
TOP_VULNERABILITIES = 60      # reverse CVE lookups from CAPEC / ATT&CK: highest base score first;
                              # enough to show CVEs from several CWEs (the total is counted separately)
MAX_IDS_WITH_CONTEXT = 3
TRAVERSE_LIMIT = 200          # ids kept for relationship checks
DISPLAY_LIMIT = 12            # related nodes shown / passed to generation per group


# node types that are not answers themselves: label -> (path, label reached, wording)
_CONCEPTS: dict[str, tuple[tuple[Hop, ...], str, str]] = {
    LABEL_PRODUCT: (((REL_AFFECTS, "in", LABEL_CVE),), LABEL_CVE, "CVEs affect"),
    LABEL_VENDOR: (((REL_MADE_BY, "in", LABEL_PRODUCT), (REL_AFFECTS, "in", LABEL_CVE)),
                   LABEL_CVE, "CVEs affect products of"),
    LABEL_TACTIC: (((REL_HAS_TACTIC, "in", LABEL_ATTACK),), LABEL_ATTACK, "ATT&CK techniques serve the tactic"),
    LABEL_MITIGATION: (((REL_MITIGATES, "out", LABEL_ATTACK),), LABEL_ATTACK,
                       "ATT&CK techniques are mitigated by"),
}
_PREVENT_RE = re.compile(r"^(?!.*\bhow (does|do) (a|an|the)\b).*\b(prevent\w*|mitigat\w*|defend\w*|avoid\w*|stop|fix|"
                         r"protect\w*\s+(against|from|myself|ourselves|my|our))\b", re.I)
_NAMED_RE = re.compile(r"\b(called|named|titled|known as|described as)\b", re.I)
_CONCEPT_FILLER = frozenset("""latest recent newest new critical high severe dangerous serious top worst
common biggest important belong belongs under part category mitigated prevent prevents addressed""".split())


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
        self.nvd = NVDLookup(settings)
        self._lexicon: Lexicon | None = None
        self._lexicon_version = ""
        self._lexicon_checked = 0.0
        self._lexicon_lock = threading.Lock()
        self._spell: SpellCorrector | None = None
        self._names: dict[str, list[dict]] = {}
        self._spell_version: str | None = None
        self._spell_lock = threading.Lock()

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

    def _speller(self) -> SpellCorrector | None:
        """Vocabulary of the current graph; rebuilt when the graph's records change."""
        with self._spell_lock:
            try:
                version = self.db.foundation_version()
                if self._spell is None or version != self._spell_version:
                    rows = self.db.vocabulary()
                    texts, brands = [], []
                    names: dict[str, list[dict]] = {}
                    for row in rows:
                        if row["label"] in (LABEL_PRODUCT, LABEL_VENDOR):
                            brands.append(row["name"])
                        else:
                            texts.append((" ".join([row["name"] or "", *(row["other"] or [])]), 5))
                            texts.append((row["text"], 1))
                        if row["label"] in _CONCEPTS and row["name"]:
                            key = " ".join(phrase_tokens(row["name"]))
                            names.setdefault(key, []).append(row)
                            vendor = " ".join(phrase_tokens(row["vendor"] or ""))
                            if vendor and key.startswith(vendor + " ") and row["cves"] >= 15:
                                names.setdefault(key[len(vendor) + 1:], []).append(row)
                    extra = (DOMAIN_VOCABULARY | QUESTION_STOPWORDS | _DATASET_WORDS | _CVE_GENERIC
                             | {w for p, _ in _GENERAL_PHRASES for w in p.split()} | _GENERAL_FILLERS
                             | {w for n in CVE_NICKNAMES for w in n.split()})
                    self._spell = SpellCorrector(texts, (w for w in extra if len(w) > 2), brands, CVE_NICKNAMES)
                    self._names, self._spell_version = names, version
            except Exception as exc:
                log.warning("Spelling correction is unavailable (%s)", type(exc).__name__)
            return self._spell

    def retrieve(self, message: str, after: str | None = None) -> RetrievalResult:
        """``after``: only the steps that follow this one ("graph" or "semantic")."""
        speller = self._speller()
        corrected, changes = speller.correct(message) if speller else (message, [])
        result = self._retrieve(corrected, after)
        if changes:
            result.corrections = changes
            result.note = (("Spelling interpreted: "
                            + ", ".join(f'"{a}" as "{b}"' for a, b in changes[:6]) + ". ")
                           + result.note).strip()
        self._measure(result)
        return result

    def _measure(self, result: RetrievalResult) -> None:
        """Properties of the retrieval the confidence score is computed from."""
        if not result.found or not result.evidence:
            return
        analysis, top = result.analysis, result.evidence[0]
        words = [t for t in analysis.content if t not in _DATASET_WORDS] or analysis.content
        title = f"{top.identifier or ''} {top.title or ''}"
        similarity = 0.0
        if result.statistics is None and not analysis.identifiers:
            try:
                question = self.embedder.embed_query(analysis.message)
                passage = self.embedder.embed_one(clean_text(f"{top.title or ''}. {top.text}", 1200))
                if question and passage:
                    similarity = sum(a * b for a, b in zip(question, passage))
            except Exception as exc:
                log.warning("Similarity could not be measured (%s)", type(exc).__name__)
        result.features = {
            "exact_id": 1.0 if (analysis.identifiers and not (top.kind != "live" and any("was not found" in m for m in result.missing)))
            or result.statistics is not None or find_nickname(analysis.message) else 0.0,
            "similarity": similarity,
            "coverage": self._text_coverage(words, f"{title} {top.text}"),
            "name_match": self._text_coverage(words, title),
            "corrected_share": min(1.0, len(result.corrections) / max(1, len(analysis.content))),
        }

    def _retrieve(self, message: str, after: str | None = None) -> RetrievalResult:
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
            result = self._retrieve_statistics(analysis)
            result.method, result.tried = GRAPH, [GRAPH]
            return result
        return self._search(analysis, after)

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
            reverse_cves = hops[-1][2] == LABEL_CVE and len(hops) >= 2
            if reverse_cves:
                result = self.db.traverse(label, identifier, hops, limit=TOP_VULNERABILITIES,
                                          order_by_score=True)
            else:
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
        result.tried = [GRAPH]
        live = self._live_cves(result, absent) if absent else []
        if not result.contexts and live:
            result.status, result.method, result.category = STATUS_FOUND, OTHER, CATEGORY_CVE
            self._check_live(result, live, absent)
            return result
        if not result.contexts:
            result.reason = "identifier(s) not present in the knowledge graph: " + ", ".join(absent)
            return result
        result.status = STATUS_FOUND
        result.method = GRAPH
        result.category = _L[result.contexts[0].label]
        for context in result.contexts:
            self._add_context(result, context)
        self._check_live(result, live, absent)
        self._check_pairs(result)
        return result

    def _live_cves(self, result: RetrievalResult, absent: list[str]) -> list[dict]:
        """CVEs the graph does not hold, read from the NVD. (Meaning says nothing about an
        identifier, so the vector search is not used for one.)"""
        rows = []
        for identifier in [i for i in absent if i.startswith("CVE-")][:MAX_IDS_WITH_CONTEXT]:
            if self.nvd.enabled and OTHER not in result.tried:
                result.tried.append(OTHER)
            row, answered = self.nvd.cve(identifier)
            if row:
                rows.append(row)
            elif answered:
                result.missing.append(f"The NVD has no record of {identifier} either.")
        return rows

    def _check_live(self, result: RetrievalResult, live: list[dict], absent: list[str]) -> None:
        for identifier in absent:
            result.missing.append(f"{identifier} was not found in the knowledge graph.")
        for row in live:
            self._add_live(result, row)
        if live:
            result.note = (", ".join(r["id"] for r in live) + ": not in the knowledge graph; "
                           "the record was read live from the NVD.").strip()

    def _add_live(self, result: RetrievalResult, row: dict, weaknesses: int = 2) -> None:
        rejected = " (REJECTED by the NVD)" if row.get("vuln_status") == "Rejected" else ""
        result.evidence.append(Evidence(
            kind="live", source="NVD (live lookup, not in the knowledge graph)", identifier=row["id"],
            title=row["id"] + rejected, text=describe_entity(LABEL_CVE, row), url=row["source_url"]))
        self._collect_mitigations(result, LABEL_CVE, row, limit=2)
        for cwe in row["related_cwe_ids"][:weaknesses]:
            node = self.db.get_node(LABEL_CWE, cwe)
            if node:
                result.evidence.append(Evidence(
                    kind="entity", source=SOURCE_NAMES[CATEGORY_CWE], identifier=cwe, title=node.get("name"),
                    text=describe_entity(LABEL_CWE, node), url=node.get("source_url")))
                self._collect_mitigations(result, LABEL_CWE, node, limit=3)

    def _add_context(self, result: RetrievalResult, context: EntityContext) -> None:
        node, label = context.node, context.label
        result.evidence.append(Evidence(
            kind="entity", source=SOURCE_NAMES[_L[label]], identifier=node["id"],
            title=node.get("name") or node["id"], text=describe_entity(label, node),
            url=node.get("source_url")))
        self._collect_mitigations(result, label, node, limit=6)
        upstream = reverse_upstream(context)
        for group in context.groups:
            if group.label == LABEL_CVE and group.direction == "in":
                if not group.nodes:
                    result.missing.append(reverse_gap(context))
                    continue
                shown = group.shown()
                more = f" (showing the {len(shown)} highest-scoring of {group.total:,})" \
                    if group.total > len(shown) else ""
                for related in group.nodes:
                    for via in related.get("via") or [node["id"]]:
                        edge = (related["id"], group.rel_type, via)
                        if edge not in result.relationships:
                            result.relationships.append(edge)
                lines = [cve_line(n, upstream, detailed=index < 6) for index, n in enumerate(shown)]
                result.evidence.append(Evidence(
                    kind="entity", source=SOURCE_NAMES[CATEGORY_CVE],
                    identifier=", ".join(n["id"] for n in shown[:6]) + (" ..." if len(shown) > 6 else ""),
                    title=f"{group.relation} for {node['id']}: {group.total:,} CVEs in the graph{more}",
                    text="\n".join(lines)))
                continue
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
        with self._lexicon_lock:
            now = time.monotonic()
            if self._lexicon is None or now - self._lexicon_checked > 60:
                version = self.db.foundation_version()
                if self._lexicon is None or version != self._lexicon_version:
                    self._lexicon = Lexicon(self.db.list_terms(),
                                            self.db.list_document_sections())
                    self._lexicon_version = version
                self._lexicon_checked = now
            return self._lexicon

    def _query_vector(self, analysis: QueryAnalysis) -> list[float] | None:
        try:
            return self.embedder.embed_query(analysis.message)
        except Exception as exc:
            log.warning("Query embedding failed (%s); continuing without vector search",
                        type(exc).__name__)
            return None

    def _question(self, analysis: QueryAnalysis) -> Question:
        tokens, content, message = analysis.tokens, analysis.content, analysis.message
        upper_words = {w.lower() for w in re.findall(r"\b(?=\w*[A-Z]\w*[A-Z])[A-Za-z0-9&]+\b", message)}
        matches, covered = self._get_lexicon().match(tokens, upper_words, content)
        positions = [i for i, t in enumerate(tokens) if t in content]
        coverage = sum(1 for i in positions if i in covered) / len(positions) if positions else 0.0
        domain_hits = [t for i, t in enumerate(tokens)
                       if t in content and (i in covered or t in DOMAIN_VOCABULARY
                                            or stem(t) in DOMAIN_VOCABULARY)]
        # A word the glossary does not know (usually a product name) next to a
        # vulnerability word or an impact ("buffer overflow in Apache Tomcat") means the
        # question is about specific records, not about the concept itself.
        other_dataset = any(label != LABEL_CVE for label in analysis.intent_labels)
        cve_question = bool(_CVE_QUESTION_RE.search(message)) and not other_dataset
        groups = cve_search_terms(message)[0]
        known = {tokens[i] for i in covered} | DOMAIN_VOCABULARY
        specific = any(" " not in g[0] and g[0] not in known and stem(g[0]) not in known for g in groups)
        # An incident in everyday words, or "which weaknesses lead to SQL injection?":
        # mapped onto ATT&CK, CAPEC and CWE and followed both ways. A question
        # about a named product's vulnerabilities keeps the CVE description search.
        mapping = bool(_MAPPING_RE.search(message)) and bool(
            analysis.intent_labels or _CVE_QUESTION_RE.search(message)) and not specific
        # "what is SQL injection and how do I prevent it": the weakness with its
        # mitigations, after the glossary definition
        prevention = (bool(_PREVENT_RE.search(message)) and not specific
                      and bool(matches) and coverage >= 0.5)
        return Question(
            analysis=analysis, matches=matches, term_coverage=coverage, domain_hits=domain_hits,
            groups=groups, other_dataset=other_dataset, cve_question=cve_question, specific=specific,
            impact_and_product=specific and not other_dataset and any(" " in g[0] for g in groups),
            scenario=is_scenario(message), mapping=mapping, prevention=prevention)

    def _vector(self, q: Question) -> list[float] | None:
        """The query embedding, computed only when the semantic step is reached."""
        if not q._vector:
            q._vector.append(self._query_vector(q.analysis))
        return q._vector[0]

    def _search(self, analysis: QueryAnalysis, after: str | None = None) -> RetrievalResult:
        """Graph first, then semantic, then other sources; the first answer is used."""
        q, tried = self._question(analysis), []
        for step, find in zip(STEPS, (self._step_graph, self._step_semantic, self._step_other)):
            if after and STEPS.index(step) <= STEPS.index(after):
                continue
            tried.append(step)
            result = find(q)
            if result is not None:
                result.method, result.tried = step, tried
                return result
        if q.named_miss:
            return RetrievalResult(STATUS_NOT_FOUND, CATEGORY_CVE, True, analysis, skip_llm=True, tried=tried,
                                   reason="no CVE description matches the described vulnerability")
        if q.domain_hits or analysis.intent_labels:
            category = _L[analysis.intent_labels[0]] if analysis.intent_labels else CATEGORY_FUNDAMENTALS
            return RetrievalResult(STATUS_NOT_FOUND, category, True, analysis, tried=tried,
                                   skip_llm=bool(analysis.intent_labels),
                                   reason="cybersecurity question without sufficient evidence")
        return RetrievalResult(STATUS_UNSUPPORTED, CATEGORY_UNSUPPORTED, False, analysis, tried=tried,
                               reason="outside the supported knowledge categories")

    # -- step 1: the graph ------------------------------------------------- #
    def _step_graph(self, q: Question) -> RetrievalResult | None:
        analysis = q.analysis
        nickname = find_nickname(analysis.message)
        if nickname:
            named = self._cve_by_nickname(analysis, *nickname)
            if named is not None:
                return named
        concept = self._concept_search(analysis)
        if concept is not None:
            return concept
        if q.mapped:
            # a definition would not answer these: without a named record, meaning decides
            return self._mapped(q, None)
        if (q.cve_question or q.impact_and_product) and (q.specific or not q.defined):
            q.described_tried = True
            described = self._cve_description_search(analysis, min_groups=1 if q.cve_question else 2)
            if described is not None:
                return described
            if q.cve_question and q.specific:
                # A vulnerability in a named product was asked for and no record
                # describes it: defining the general terms instead would mislead.
                q.named_miss = True
                return None
        if q.defined and not analysis.strong_intent:
            result = self._fundamentals_result(analysis, q.matches, None)
            self._follow_term(result, q.matches)
            return result
        if q.cve_question and not q.described_tried:
            described = self._cve_description_search(analysis, min_groups=1)
            if described is not None:
                return described
        if analysis.intent_labels or not q.matches:
            return self._entity_search(analysis, None)
        return None

    def _mapped(self, q: Question, vector) -> RetrievalResult | None:
        mapped = self._threat_mapping(q.analysis, q.scenario, vector)
        if mapped is not None and q.prevention:
            definition = self._fundamentals_result(q.analysis, q.matches, None).evidence[:2]
            mapped.evidence[1:1] = definition
            if definition:
                mapped.note = f"{definition[0].text} (Source: {definition[0].source}) " + mapped.note
        return mapped

    # -- step 2: vector similarity ----------------------------------------- #
    def _step_semantic(self, q: Question) -> RetrievalResult | None:
        analysis = q.analysis
        vector = self._vector(q)
        if not vector:
            return None
        if q.named_miss:
            return self._semantic_fallback(analysis, vector, (LABEL_CVE,), named=True)
        if q.mapped:
            mapped = self._mapped(q, vector)
            if mapped is not None:
                return mapped
        if analysis.intent_labels or not q.matches:
            entity = self._entity_search(analysis, vector)
            if entity is not None:
                return entity
        semantic = self._fundamentals_semantic(analysis, vector)
        if semantic is not None:
            return semantic
        # a question in everyday words about no product: a technique, weakness or term by
        # meaning fits better than a CVE that happens to contain the same words
        if not q.cve_question and not q.other_dataset and not q.impact_and_product and q.domain_hits:
            by_meaning = self._semantic_fallback(
                analysis, vector, (LABEL_ATTACK, LABEL_CAPEC, LABEL_CWE, LABEL_TERM), named=False)
            if by_meaning is not None:
                return by_meaning
        labels = ([l for l in analysis.intent_labels if l != LABEL_CVE] if q.other_dataset
                  else (LABEL_CVE,) if q.cve_question else
                  (LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK, LABEL_TERM, LABEL_DOC, LABEL_TACTIC,
                   LABEL_MITIGATION) + ((LABEL_CVE,) if q.domain_hits else ()))
        return self._semantic_fallback(analysis, vector, labels, named=False, strict=not q.domain_hits)

    # -- step 3: other sources --------------------------------------------- #
    def _step_other(self, q: Question) -> RetrievalResult | None:
        analysis = q.analysis
        if q.defined and not q.named_miss:       # a definition, although a dataset was asked for
            return self._fundamentals_result(analysis, q.matches, None)
        if (not q.described_tried and not q.cve_question and not q.other_dataset
                and (q.domain_hits or analysis.intent_labels)):
            described = self._cve_description_search(analysis, min_groups=2)
            if described is not None:
                return described
        if q.named_miss or (q.cve_question and q.specific):
            return self._live_search(q)
        return None

    def _live_search(self, q: Question) -> RetrievalResult | None:
        rows, total = self.nvd.search([g[0] for g in q.groups][:6])
        if not rows:
            return None
        result = RetrievalResult(STATUS_FOUND, CATEGORY_CVE, True, q.analysis,
                                 identifiers=[r["id"] for r in rows])
        for row in rows:
            self._add_live(result, row, weaknesses=0)
        result.note = (f"Nothing in the knowledge graph matched, so the NVD was searched live: {total:,} "
                       f"record{'s' if total != 1 else ''} matched"
                       + (f"; the newest {len(rows)} are shown." if total > len(rows) else "."))
        return result

    # -- vector search over several indexes ------------------------------- #
    def _semantic_fallback(self, analysis: QueryAnalysis, vector, labels, named: bool,
                           strict: bool = False) -> RetrievalResult | None:
        """The closest records by meaning. ``named``: the question names a product, so a CVE
        must mention one of its unusual words. ``strict``: no security word in the question."""
        if not vector or self.embedder.provider == "local":
            return None                          # feature hashing does not capture meaning
        # a record asked for by name, or a word nobody knows: the nearest other record
        # would be a wrong answer, not a helpful one
        if _NAMED_RE.search(analysis.message) or (not named and self._spell is not None and any(
                t.isalpha() and len(t) > 3 and not self._spell.known(t) for t in analysis.content)):
            return None
        floor = self.tuning.semantic_accept + (0.06 if strict else 0.0)
        hits = [h for label in labels for h in self.db.vector_search(label, vector, 8)]
        hits = [h for h in hits if 2 * h["_score"] - 1 >= floor]
        if named:
            rare = [t for t in analysis.content if t not in DOMAIN_VOCABULARY and t not in _CVE_GENERIC
                    and t not in _DATASET_WORDS and not any(p.search(t) for p, _ in _CVE_CONCEPTS)]
            hits = [h for h in hits if not rare or self._text_coverage(
                rare, f"{h.get('description')} {' '.join(h.get('affected_products') or []).replace(':', ' ')}"
            ) >= 0.5]
        hits.sort(key=lambda h: -h["_score"])
        if not hits:
            return None
        best = hits[0]
        note = ("No record contains the exact wording, so the closest records by meaning were used "
                f"(similarity {2 * best['_score'] - 1:.2f}).")
        if best["_label"] in (LABEL_TERM, LABEL_DOC):
            result = RetrievalResult(STATUS_FOUND, CATEGORY_FUNDAMENTALS, True, analysis, note=note)
            for hit in [h for h in hits if h["_label"] in (LABEL_TERM, LABEL_DOC)][:5]:
                result.evidence.append(_foundation_evidence(
                    "term" if hit["_label"] == LABEL_TERM else "document", hit, hit["_score"]))
            return result
        if best["_label"] in _CONCEPTS:
            return self._concept_result(analysis, {"label": best["_label"], "id": best["id"]}, note)
        context = self.entity_context(best["_label"], best["id"])
        if context is None:
            return None
        result = RetrievalResult(STATUS_FOUND, _L[best["_label"]], True, analysis,
                                 identifiers=[best["id"]], contexts=[context], note=note)
        self._add_context(result, context)
        for other in [h for h in hits[1:] if h["_label"] in _L][:self.tuning.extra_entries + 2]:
            result.identifiers.append(other["id"])
            title = other.get("name")
            if other["_label"] == LABEL_CVE:
                title = clean_text(other.get("description") or other["id"], 260)
            result.evidence.append(Evidence(
                kind="entity", source=SOURCE_NAMES[_L[other["_label"]]], identifier=other["id"],
                title=title, text=describe_entity(other["_label"], other),
                score=other["_score"], url=other.get("source_url")))
        return result

    # -- products, vendors, tactics, mitigations by name ------------------- #
    def _concept_search(self, analysis: QueryAnalysis) -> RetrievalResult | None:
        """"vulnerabilities in Apache Tomcat", "techniques of the persistence tactic"."""
        text = " ".join(analysis.tokens)
        wants_cves = bool(_CVE_QUESTION_RE.search(analysis.message))
        wants_attack = LABEL_ATTACK in analysis.intent_labels or "mitigat" in text
        if (not wants_cves and not wants_attack) or _NAMED_RE.search(analysis.message):
            return None
        allowed = ((LABEL_PRODUCT, LABEL_VENDOR) if wants_cves and not wants_attack
                   else (LABEL_TACTIC, LABEL_MITIGATION))
        found: list[tuple[int, int, dict]] = []
        tokens = analysis.tokens
        for size in range(min(6, len(tokens)), 0, -1):
            for start in range(len(tokens) - size + 1):
                phrase = " ".join(tokens[start:start + size])
                for row in self._names.get(phrase, ()):
                    if row["label"] in allowed:
                        found.append((size, row["cves"], row))
            if found:
                break
        if not found:
            return None
        size, _, row = max(found, key=lambda f: (f[0], f[2]["label"] == LABEL_VENDOR, f[1]))
        name = set(phrase_tokens(row["name"]))
        generic = _CVE_GENERIC if row["label"] in (LABEL_PRODUCT, LABEL_VENDOR) else ()
        rest = [t for t in analysis.content if t not in name and t not in generic
                and t not in _DATASET_WORDS and t not in _CONCEPT_FILLER]
        if rest:                                 # more than the name was asked: other routes
            return None
        return self._concept_result(analysis, row, "")

    def _concept_result(self, analysis: QueryAnalysis, row: dict, note: str) -> RetrievalResult | None:
        label = row["label"]
        node = self.db.get_node(label, row["id"])
        if node is None:
            return None
        hops, target, what = _CONCEPTS[label]
        links = self.db.linked(label, row["id"], hops, limit=12)
        if not links["nodes"]:
            return None
        result = RetrievalResult(STATUS_FOUND, _L[target], True, analysis,
                                 identifiers=[n["id"] for n in links["nodes"]])
        lines = [cve_line(n, detailed=i < 8) if target == LABEL_CVE else
                 f"{n['id']}: {n.get('name')} - {clean_text(n.get('description'), 220)}"
                 for i, n in enumerate(links["nodes"])]
        if target == LABEL_CVE:                  # the path through a vendor's products is noise
            lines = [re.sub(r" via (?:product|vendor):.*?(?= - |$)", "", line) for line in lines]
        result.evidence.append(Evidence(
            kind="concept", source=SOURCE_NAMES[_L[target]], identifier=node["name"], title=node["name"],
            text=f"{node.get('description') or ''}\n" + "\n".join(lines)))
        for n in links["nodes"][:5]:
            result.evidence.append(Evidence(
                kind="entity", source=SOURCE_NAMES[_L[target]], identifier=n["id"],
                title=n.get("name"), text=describe_entity(target, n), url=n.get("source_url")))
            self._collect_mitigations(result, target, n, limit=2)
        shown = len(links["nodes"])
        result.note = (f"{note} {links['total']:,} {what} {node['name']} in the knowledge graph"
                       + (f"; {shown} are shown." if links["total"] > shown else ".")).strip()
        return result

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

    def _follow_term(self, result: RetrievalResult, matches) -> None:
        """A question about one term only ("what is SQL injection"): after the definition, the
        weakness, attack pattern or technique of exactly that name with its relationships."""
        def key(text: str) -> tuple[str, ...]:
            return tuple(stem(t) for t in phrase_tokens(text))

        asked = tuple(stem(t) for t in result.analysis.content if t not in _DATASET_WORDS)
        names: dict[tuple[str, ...], str] = {}
        for kind, row, _ in matches:
            aliases = {key(a): a for a in row.get("aliases") or []} if kind == "term" else {}
            if asked and asked in aliases:
                names.update(aliases)
        order, best = (LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK), None
        for name in names.values():
            for hit in self.db.name_search(name, list(order), k=12):
                # a sub-technique is one narrow use of the term ("SSH": T1021.004 only)
                if hit["_label"] == LABEL_ATTACK and "." in hit["id"]:
                    continue
                if any(key(n) in names for n in [hit.get("name") or "", *(hit.get("alternate_terms") or [])]):
                    rank = (order.index(hit["_label"]), hit["id"])
                    best = min(best, rank) if best else rank
        context = self.entity_context(order[best[0]], best[1]) if best else None
        if context is not None:
            result.identifiers, result.contexts = [best[1]], [context]
            self._add_context(result, context)

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
    # -- threat mapping ------------------------------------------------------ #
    def _threat_mapping(self, analysis: QueryAnalysis, scenario: bool, vector) -> RetrievalResult | None:
        """Match a described incident or concept to the closest ATT&CK technique, CAPEC
        attack pattern and CWE weakness, and return each with its relationships in both
        directions (down to example CVEs). Nothing is inferred: only graph records.
        Without ``vector`` (graph step) a record counts only when the question names it."""
        hints = scenario_hints(analysis.message) if scenario else ""
        subject = [t for t in analysis.content if t not in _DATASET_WORDS]
        if not subject and not hints:
            return None
        wanted = [l for l in analysis.intent_labels if l != LABEL_CVE]
        labels = wanted + [l for l in (LABEL_ATTACK, LABEL_CAPEC, LABEL_CWE) if l not in wanted]
        semantic = bool(vector)
        if semantic and hints:
            vector = self.embedder.embed_query(f"{analysis.message} {hints}".strip())
        asked = {stem(t) for t in analysis.tokens}
        candidates: dict[str, dict] = {}

        def add(hit: dict, name_bonus: float = 0.0) -> None:
            entry = candidates.setdefault(hit["id"], {**hit, "_vec": 0.0, "_name": 0.0})
            entry["_name"] = max(entry["_name"], name_bonus)

        for text, bonus in ((" ".join(subject), 1.0), (hints, 0.6)):
            if text.strip():
                for hit in self.db.name_search(text, labels, k=self.tuning.name_search_k * (1 if semantic else 3)):
                    if not semantic:
                        named = (_named_share(hit, asked, subject) if bonus == 1.0
                                 else _named_phrase(hit, phrase_tokens(hints)))
                        if named:
                            add(hit, named)
                        continue
                    name_text = " ".join([hit.get("name") or ""] + list(hit.get("alternate_terms") or []))
                    coverage = self._text_coverage(subject, name_text) if bonus == 1.0 else 0.5
                    if coverage >= 0.75 or bonus < 1.0:
                        add(hit, bonus * coverage)
        for label in labels:
            for hit in self._vector_hits(label, vector, max(6, self.tuning.vector_k)):
                add(hit)
                candidates[hit["id"]]["_vec"] = max(candidates[hit["id"]]["_vec"], hit["_score"])
        if not candidates:
            return None
        for entry in candidates.values():
            entry["_rank"] = entry["_vec"] + 0.35 * entry["_name"]
        ranked = sorted(candidates.values(), key=lambda e: -e["_rank"])
        usable = ranked if not semantic else [e for e in ranked if e["_vec"] > 0 or e["_name"] >= 0.75]
        if not usable:
            return None
        # The strongest match first. The other entity types then prefer entries the
        # graph links to it (SQL Injection -> CWE-89, not just a similar-sounding CWE),
        # and fall back to the closest match by meaning.
        result = RetrievalResult(STATUS_FOUND, _L[usable[0]["_label"]], True, analysis)
        first = self.entity_context(usable[0]["_label"], usable[0]["id"])
        if first is None:
            return None
        chosen = [first]
        for label in [l for l in labels if l != usable[0]["_label"]]:
            if len(chosen) >= MAX_IDS_WITH_CONTEXT:
                break
            linked = [n["id"] for g in first.groups if g.label == label for n in g.nodes]
            pick = next((e["id"] for e in usable if e["_label"] == label and e["id"] in linked), None)
            if pick is None and linked:
                pick = linked[0]
            if pick is None:
                pick = next((e["id"] for e in usable if e["_label"] == label), None)
            if pick is not None and pick not in {c.node["id"] for c in chosen}:
                context = self.entity_context(label, pick)
                if context is not None:
                    chosen.append(context)
        for context in chosen:
            result.contexts.append(context)
            result.identifiers.append(context.node["id"])
            self._add_context(result, context)
        best = [{"id": c.node["id"]} for c in chosen]
        shown = {e["id"] for e in best}
        for other in [e for e in ranked if e["id"] not in shown][:self.tuning.extra_entries]:
            result.identifiers.append(other["id"])
            result.evidence.append(Evidence(
                kind="entity", source=SOURCE_NAMES[_L[other["_label"]]], identifier=other["id"],
                title=other.get("name"), text=describe_entity(other["_label"], other),
                score=other.get("_score"), url=other.get("source_url")))
        names = ", ".join(f"{c.node['id']} ({c.node.get('name') or c.label})" for c in result.contexts)
        if scenario:
            result.note = (
                "No identifier was given, so the situation described was matched "
                f"{'by meaning' if semantic else 'by name'} against "
                f"MITRE ATT&CK, CAPEC and CWE. The closest entries in the knowledge graph are {names}; "
                "they are shown with their relationships in both directions, including example CVEs. "
                "They indicate what kind of attack and weakness may be involved; they are not a "
                "diagnosis of a specific device.")
        else:
            result.note = (
                f"No identifier was given, so the question was matched to {names} in the knowledge "
                "graph and their relationships are followed in both directions (forward to attack "
                "patterns and techniques, backward to weaknesses and example CVEs).")
        return result

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
def _named_share(hit: dict, asked: set[str], subject: Sequence[str]) -> float:
    """How fully the question names this record (0 = it does not): every word of one of its
    names must be in the question, and a one-word name must be a good part of the subject."""
    name = hit.get("name") or ""
    best = 0.0
    wanted = {stem(t) for t in subject}
    for alias in [name, *re.findall(r"\('([^']+)'\)", name), *(hit.get("alternate_terms") or [])]:
        words = {stem(t) for t in content_tokens(phrase_tokens(alias))}
        if not words or not words <= asked or not words & wanted:
            continue
        share = len(words & wanted) / len(wanted)
        if len(words) >= 2 or share >= 0.5:
            best = max(best, share)
    return best


def _named_phrase(hit: dict, hint_tokens: Sequence[str]) -> float:
    """The security wording behind an everyday description contains this record's name as a
    phrase: the earlier it comes, the closer the description (at most 0.6)."""
    hint = [stem(t) for t in hint_tokens]
    best = 0.0
    for alias in [hit.get("name") or "", *(hit.get("alternate_terms") or [])]:
        words = [stem(t) for t in phrase_tokens(alias)]
        for start in range(len(hint) - len(words) + 1) if words else ():
            if hint[start:start + len(words)] == words:
                best = max(best, 0.6 - 0.02 * start)
                break
    return max(best, 0.0)


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


def reverse_upstream(context: EntityContext) -> dict[str, list[str]]:
    """For an ATT&CK technique: CWE id -> the CAPEC ids that link it to the technique,
    so a CVE reached in reverse can show its whole path (CVE -> CWE -> CAPEC -> ATT&CK)."""
    if context.label != LABEL_ATTACK:
        return {}
    return {n["id"]: n.get("via") or [] for g in context.groups
            if g.label == LABEL_CWE and g.direction == "in" for n in g.nodes}


def cve_line(node: dict, upstream: dict[str, list[str]] | None = None,
             detailed: bool = True) -> str:
    """One CVE reached by a reverse traversal: score, date, path and (optionally) text."""
    facts = []
    if node.get("base_score") is not None:
        facts.append(f"CVSS {node['base_score']}" + (f" {node['severity']}" if node.get("severity") else ""))
    else:
        facts.append("no CVSS score from NVD")
    if node.get("published"):
        facts.append(f"published {str(node['published'])[:10]}")
    paths = []
    for cwe in node.get("via") or []:
        capecs = (upstream or {}).get(cwe) or []
        paths.append(cwe + (f" <- {', '.join(capecs[:3])}" if capecs else ""))
    line = f"{node['id']} ({', '.join(facts)})"
    if paths:
        line += f" via {'; '.join(paths[:3])}"
    if detailed and node.get("description"):
        line += f" - {clean_text(node['description'], 260)}"
    return line


def reverse_gap(context: EntityContext) -> str:
    """Explain where a reverse traversal towards CVEs stopped."""
    node_id, label = context.node["id"], context.label
    by_label = {g.label: g for g in context.groups if g.direction == "in"}
    if label == LABEL_ATTACK and not (by_label.get(LABEL_CAPEC) and by_label[LABEL_CAPEC].nodes):
        return (f"No CVE is linked to {node_id}: MITRE lists no CAPEC attack pattern for this "
                "technique, so the graph has no CAPEC -> CWE -> CVE path from it (most ATT&CK "
                "techniques have no CAPEC mapping). Its sub-techniques or parent technique may have one.")
    if label in (LABEL_ATTACK, LABEL_CAPEC) and not (by_label.get(LABEL_CWE) and by_label[LABEL_CWE].nodes):
        return (f"No CVE is linked to {node_id}: the CAPEC attack pattern(s) on its path list no "
                "CWE weakness, so the graph has no CWE -> CVE path from it.")
    return (f"No CVE in the knowledge graph lists the CWE weakness(es) linked to {node_id}.")


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
