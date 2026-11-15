"""Shared data-processing utilities and foundational-document ingestion.

This module contains everything the updaters and the RAG pipeline share:

* resilient HTTP downloads (timeouts, retry, exponential backoff);
* XML / ZIP / STIX-JSON helpers and identifier normalisation;
* hashing for change detection, validation and text cleaning;
* embedding generation behind a configurable provider;
* extraction of the approved reference documents (PDF / Markdown / text) into
  ``CyberDocument`` chunks and ``CyberTerm`` records, with page references.

Downloaded and extracted content is always treated as *data*: it is cleaned,
validated and stored, never interpreted as instructions.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import re
import time
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from xml.etree import ElementTree as ET

import httpx

from backend.config import Settings
from backend.database import LABEL_DOC, LABEL_TERM, utc_now_iso

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class FetchError(RuntimeError):
    """An external source could not be downloaded after all retries."""


class DataValidationError(ValueError):
    """Downloaded content is malformed or fails validation."""


# --------------------------------------------------------------------------- #
# HTTP with retry and exponential backoff
# --------------------------------------------------------------------------- #
RETRY_STATUSES = frozenset({403, 408, 425, 429, 500, 502, 503, 504})


def build_http_client(settings: Settings) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(settings.http_timeout_seconds, connect=20.0),
        follow_redirects=True,
        headers={"User-Agent": "RAG-Cyber/1.0 (cybersecurity knowledge-graph updater)"},
    )


def http_get(client: httpx.Client, url: str, *, params: dict | None = None,
             headers: dict | None = None, max_retries: int = 5, backoff_base: float = 2.0,
             sleep: Callable[[float], None] = time.sleep) -> httpx.Response:
    """GET with retry + exponential backoff.  Never logs headers or parameters."""
    host = httpx.URL(url).host
    last_error = "unknown error"
    for attempt in range(max_retries + 1):
        try:
            response = client.get(url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}"
        else:
            if response.status_code == 200:
                return response
            last_error = f"HTTP {response.status_code}"
            if response.status_code not in RETRY_STATUSES:
                raise FetchError(f"{host} answered {last_error}; not retrying")
            retry_after = response.headers.get("Retry-After", "")
            if retry_after.isdigit():
                sleep(min(float(retry_after), 120.0))
        if attempt < max_retries:
            delay = min(backoff_base * (2 ** attempt), 120.0)
            log.warning("Request to %s failed (%s); retry %d/%d in %.0fs",
                        host, last_error, attempt + 1, max_retries, delay)
            sleep(delay)
    raise FetchError(f"{host} could not be reached after {max_retries + 1} attempts "
                     f"({last_error})")


# --------------------------------------------------------------------------- #
# Text, hashing, validation, identifier normalisation
# --------------------------------------------------------------------------- #
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RE = re.compile(r"\s+")


def clean_text(value: Any, max_chars: int | None = None) -> str:
    """Remove control characters and collapse whitespace."""
    if value is None:
        return ""
    text = _WS_RE.sub(" ", _CONTROL_RE.sub(" ", str(value))).strip()
    if max_chars is not None and len(text) > max_chars:
        text = text[:max_chars].rsplit(" ", 1)[0] + " ..."
    return text


def content_hash(value: Any) -> str:
    """Stable SHA-256 of any JSON-serialisable value (change detection)."""
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def dedupe(items: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        if item and item not in seen:
            seen[item] = None
    return list(seen)


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_ID_RE = re.compile(r"^CWE-\d+$")
CAPEC_ID_RE = re.compile(r"^CAPEC-\d+$")
ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalize_cve_id(raw: Any) -> str | None:
    value = clean_text(raw).upper()
    return value if CVE_ID_RE.match(value) else None


def normalize_cwe_id(raw: Any) -> str | None:
    """'89', 'CWE-89', 'cwe 89' -> 'CWE-89'.  NVD placeholders -> None."""
    match = re.fullmatch(r"(?:CWE[-\s]?)?(\d+)", clean_text(raw).upper())
    return f"CWE-{int(match.group(1))}" if match else None


def normalize_capec_id(raw: Any) -> str | None:
    match = re.fullmatch(r"(?:CAPEC[-\s]?)?(\d+)", clean_text(raw).upper())
    return f"CAPEC-{int(match.group(1))}" if match else None


def normalize_attack_id(raw: Any) -> str | None:
    """'1574.010', 'T1574.010', 't1059' -> canonical ATT&CK technique id."""
    match = re.fullmatch(r"T?(\d{4})(?:\.(\d{3}))?", clean_text(raw).upper())
    if not match:
        return None
    return f"T{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else "")


def require_fields(row: dict, fields: Sequence[str], kind: str) -> None:
    missing = [f for f in fields if row.get(f) in (None, "", [])]
    if missing:
        raise DataValidationError(f"{kind} record {row.get('id')!r} is missing {missing}")


# --------------------------------------------------------------------------- #
# XML / ZIP helpers
# --------------------------------------------------------------------------- #
MAX_XML_BYTES = 400 * 1024 * 1024


def unzip_single_xml(data: bytes) -> bytes:
    """Return the XML payload of a MITRE download (plain XML or a ZIP with one)."""
    if not data.startswith(b"PK"):
        return data
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [m for m in archive.infolist() if m.filename.lower().endswith(".xml")]
            if not members:
                raise DataValidationError("ZIP archive contains no XML file")
            member = max(members, key=lambda m: m.file_size)
            if member.file_size > MAX_XML_BYTES:
                raise DataValidationError("XML file in archive is unreasonably large")
            return archive.read(member)
    except zipfile.BadZipFile as exc:
        raise DataValidationError("Downloaded archive is not a valid ZIP file") from exc


def parse_xml(data: bytes) -> ET.Element:
    """Parse untrusted XML.  Documents carrying a DTD are refused outright, which
    rules out entity-expansion and external-entity tricks."""
    payload = unzip_single_xml(data)
    if b"<!DOCTYPE" in payload[:4096] or b"<!ENTITY" in payload[:4096]:
        raise DataValidationError("XML with a DOCTYPE/ENTITY declaration is not accepted")
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise DataValidationError(f"Malformed XML: {exc}") from exc


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def xml_children(element: ET.Element | None, name: str) -> list[ET.Element]:
    if element is None:
        return []
    return [child for child in element if local_name(child.tag) == name]


def xml_child(element: ET.Element | None, name: str) -> ET.Element | None:
    found = xml_children(element, name)
    return found[0] if found else None


def xml_text(element: ET.Element | None, max_chars: int | None = None) -> str:
    """All text inside an element (MITRE descriptions embed XHTML markup)."""
    if element is None:
        return ""
    return clean_text(" ".join(element.itertext()), max_chars)


def xml_descendants(element: ET.Element | None, name: str) -> list[ET.Element]:
    if element is None:
        return []
    return [node for node in element.iter() if local_name(node.tag) == name]


# --------------------------------------------------------------------------- #
# STIX helpers
# --------------------------------------------------------------------------- #
def load_stix_bundle(data: bytes) -> list[dict]:
    try:
        bundle = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DataValidationError(f"Malformed STIX JSON: {exc}") from exc
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if bundle.get("type") != "bundle" or not isinstance(objects, list):
        raise DataValidationError("STIX payload is not a bundle with an 'objects' list")
    return [obj for obj in objects if isinstance(obj, dict)]


def stix_external_ids(obj: dict, source_names: Sequence[str]) -> list[tuple[str, str]]:
    """(external_id, url) pairs from the given external-reference sources."""
    result = []
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") in source_names and ref.get("external_id"):
            result.append((str(ref["external_id"]), str(ref.get("url") or "")))
    return result


# --------------------------------------------------------------------------- #
# Embeddings
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[&+#][a-z0-9]*)?")
EMBED_STOPWORDS = frozenset(
    "a an and are as at be by for from has have in is it its of on or that the this to was "
    "were which with what how why when where who can could does do did will would should "
    "i you we they he she them their our your my me us about into than then there these "
    "those such via per not no".split())


def embedding_tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in EMBED_STOPWORDS]


def local_embedding(text: str, dimensions: int) -> list[float] | None:
    """Deterministic feature-hashing embedding (unigrams + bigrams, signed hashing,
    sub-linear TF, L2-normalised).  It needs no model download or API key, which
    makes it the default for local development; it captures lexical rather than
    deep semantic similarity, so a neural provider is recommended for production.
    """
    tokens = embedding_tokens(text)
    if not tokens:
        return None
    features = Counter(tokens)
    features.update(f"{a}_{b}" for a, b in zip(tokens, tokens[1:]))
    vector = [0.0] * dimensions
    for feature, count in features.items():
        digest = zlib.crc32(feature.encode("utf-8"))
        sign = 1.0 if (digest >> 31) & 1 else -1.0
        weight = (1.0 + math.log(count)) * (0.6 if "_" in feature else 1.0)
        vector[digest % dimensions] += sign * weight
    norm = math.sqrt(sum(v * v for v in vector))
    if norm == 0:
        return None
    return [round(v / norm, 6) for v in vector]


class EmbeddingClient:
    """Configurable embedding provider (local | openai-compatible | ollama)."""

    def __init__(self, settings: Settings, http_client: httpx.Client | None = None):
        self._settings = settings
        self._client = http_client
        self._dimensions: int | None = (
            settings.embedding_dimensions if settings.embedding_provider == "local" else None)

    @property
    def provider(self) -> str:
        return self._settings.embedding_provider

    @property
    def signature(self) -> str:
        """Identifies provider+model so embeddings are refreshed when it changes."""
        s = self._settings
        if s.embedding_provider == "local":
            return f"local-hash-v1:{s.embedding_dimensions}"
        return f"{s.embedding_provider}:{s.embedding_model}"

    @property
    def dimensions(self) -> int:
        if self._dimensions is None:
            probe = self.embed(["dimension probe"])[0]
            if not probe:
                raise FetchError("Embedding provider returned no vector for the probe text")
            self._dimensions = len(probe)
        return self._dimensions

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=httpx.Timeout(self._settings.http_timeout_seconds))
        return self._client

    def embed_one(self, text: str) -> list[float] | None:
        return self.embed([text])[0]

    def embed(self, texts: Sequence[str]) -> list[list[float] | None]:
        """Embed texts; an entry is ``None`` when the text has no usable content."""
        s = self._settings
        if s.embedding_provider == "local":
            return [local_embedding(t, s.embedding_dimensions) for t in texts]
        cleaned = [clean_text(t, 6000) or "empty" for t in texts]
        vectors: list[list[float] | None] = []
        for start in range(0, len(cleaned), 64):
            batch = cleaned[start:start + 64]
            vectors.extend(self._remote_embed(batch))
        return vectors

    def _remote_embed(self, batch: list[str]) -> list[list[float]]:
        s = self._settings
        if s.embedding_provider == "openai":
            base = (s.embedding_base_url or "https://api.openai.com/v1").rstrip("/")
            url, payload = f"{base}/embeddings", {"model": s.embedding_model, "input": batch}
            headers = {"Authorization": f"Bearer {s.embedding_api_key}"} if s.embedding_api_key else {}
        else:  # ollama
            base = (s.embedding_base_url or "http://localhost:11434").rstrip("/")
            url, payload, headers = f"{base}/api/embed", {"model": s.embedding_model, "input": batch}, {}
        last_error = "unknown error"
        for attempt in range(s.http_max_retries + 1):
            try:
                response = self._http().post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    body = response.json()
                    if s.embedding_provider == "openai":
                        data = sorted(body["data"], key=lambda item: item["index"])
                        result = [item["embedding"] for item in data]
                    else:
                        result = body["embeddings"]
                    if len(result) != len(batch):
                        raise DataValidationError("Embedding count does not match input count")
                    return result
                last_error = f"HTTP {response.status_code}"
                if response.status_code not in RETRY_STATUSES:
                    break
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                last_error = type(exc).__name__
            time.sleep(min(2.0 * (2 ** attempt), 60.0))
        raise FetchError(f"Embedding provider '{s.embedding_provider}' failed ({last_error})")


def attach_embeddings(db, embedder: EmbeddingClient, label: str, rows: list[dict],
                      text_of: Callable[[dict], str]) -> int:
    """Add ``embedding`` to rows whose text (or the embedding model) changed.

    Unchanged rows carry no ``embedding`` key, so the stored vector is kept and no
    embedding call is made for them.  Returns the number of new embeddings.
    """
    if not rows:
        return 0
    existing = db.get_property_map(label, [r["id"] for r in rows], "embedding_hash")
    pending: list[tuple[dict, str, str]] = []
    for row in rows:
        text = text_of(row)
        digest = content_hash([embedder.signature, text])
        if existing.get(row["id"]) != digest:
            pending.append((row, text, digest))
    if not pending:
        return 0
    vectors = embedder.embed([text for _, text, _ in pending])
    embedded = 0
    for (row, _, digest), vector in zip(pending, vectors):
        if vector:
            row["embedding"] = vector
            row["embedding_hash"] = digest
            embedded += 1
    return embedded


EMBEDDING_TEXT: dict[str, Callable[[dict], str]] = {
    "CVE": lambda r: f"{r.get('id', '')}. {r.get('description', '')}",
    "CWE": lambda r: (f"{r.get('name', '')}. {' '.join(r.get('alternate_terms') or [])}. "
                      f"{r.get('description', '')}"),
    "CAPEC": lambda r: f"{r.get('name', '')}. {r.get('description', '')}",
    "ATTACK": lambda r: f"{r.get('name', '')}. {r.get('description', '')}",
    "CyberTerm": lambda r: f"{r.get('term', '')}. {r.get('definition', '')}",
    "CyberDocument": lambda r: f"{r.get('section') or r.get('title', '')}. {r.get('content', '')}",
}


# --------------------------------------------------------------------------- #
# Phrase normalisation shared with the retriever
# --------------------------------------------------------------------------- #
_PHRASE_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[&+#.'][a-z0-9]+)*")


def phrase_tokens(text: str) -> list[str]:
    """Lower-case word tokens ('Wi-Fi' -> ['wi', 'fi'], 'ATT&CK' -> ['att&ck'])."""
    return _PHRASE_TOKEN_RE.findall(text.lower().replace("’", "'"))


def normalize_phrase(text: str) -> str:
    return " ".join(phrase_tokens(text))


def term_aliases(term: str, extra: Sequence[str] = ()) -> list[str]:
    """Searchable name variants of a glossary term.

    'SQL Injection (SQLi)' -> ['sql injection', 'sqli'];
    'IDS / IPS' -> ['ids', 'ips'];  'Zero-Day' -> ['zero day', 'zeroday'].
    """
    variants: list[str] = []
    for part in re.split(r"\s+/\s+", term):
        part = part.strip()
        optional = re.fullmatch(r"(\w+)\((\w)\)", part)          # HTTP(S)
        if optional:
            variants += [optional.group(1), optional.group(1) + optional.group(2)]
            continue
        for inner in re.findall(r"\(([^)]+)\)", part):
            if inner and not inner[0].islower():                    # skip '(in security)'
                variants.append(inner)
        outer = re.sub(r"\([^)]*\)", " ", part).strip()
        if outer:
            variants.append(outer)
    variants += list(extra)
    aliases: list[str] = []
    for variant in variants:
        aliases.append(normalize_phrase(variant))
        if "-" in variant:
            aliases.append(normalize_phrase(variant.replace("-", "")))
    return [a for a in dedupe(aliases) if len(a) >= 2]


def slugify(text: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_len].strip("-") or "item"


# --------------------------------------------------------------------------- #
# Reference-document parsing (PDF layout analysis, Markdown / text)
# --------------------------------------------------------------------------- #
@dataclass
class Fragment:
    x: float
    y: float
    size: float
    bold: bool
    text: str
    seq: int


@dataclass
class Line:
    page: int
    y: float
    fragments: list[Fragment]
    bullet: bool = False

    @property
    def size(self) -> float:
        return max(f.size for f in self.fragments)

    @property
    def text(self) -> str:
        return clean_text(" ".join(f.text for f in self.fragments))

    @property
    def all_bold(self) -> bool:
        return all(f.bold for f in self.fragments)

    def cells(self, tolerance: float = 3.0) -> list[tuple[float, str]]:
        """Fragments grouped by their starting x position (table columns)."""
        groups: list[list] = []
        for frag in sorted(self.fragments, key=lambda f: (f.x, f.seq)):
            if groups and abs(groups[-1][0] - frag.x) <= tolerance:
                groups[-1][1].append(frag)
            else:
                groups.append([frag.x, [frag]])
        return [(x, clean_text(" ".join(f.text for f in sorted(fr, key=lambda f: f.seq))))
                for x, fr in groups]


@dataclass
class TermRecord:
    term: str
    definition: str
    category: str
    page_number: int | None
    aliases: list[str]


@dataclass
class ChunkRecord:
    section: str
    content: str
    page_number: int | None


@dataclass
class ParsedDocument:
    title: str
    source_file: str
    terms: list[TermRecord] = field(default_factory=list)
    chunks: list[ChunkRecord] = field(default_factory=list)


_BULLET_CHARS = set("•●▪■◦‣·-–*o�")
_SKIP_SECTIONS = re.compile(r"^(contents|figures|tables|references|disclaimer|"
                            r"acknowledg(e)?ments?|\d+\.\d+\s+references)$", re.I)
_GLOSSARY_HEADERS = {"term", "terms", "word", "concept", "name", "acronym", "abbreviation"}
_ACRONYM_LINE_RE = re.compile(r"^([A-Z][A-Za-z&]{1,9}):\s+([A-Z][^.:]{3,90})$")
CHUNK_TARGET_CHARS = 1100


def _is_bullet_fragment(text: str) -> bool:
    stripped = text.strip()
    return len(stripped) == 1 and stripped in _BULLET_CHARS


def extract_pdf_lines(path: Path) -> tuple[list[Line], dict]:
    """Read a PDF into positioned text lines (headers / footers removed)."""
    from pypdf import PdfReader  # imported lazily: only ingestion needs it

    reader = PdfReader(str(path))
    lines: list[Line] = []
    for page_index, page in enumerate(reader.pages, start=1):
        fragments: list[Fragment] = []

        def visitor(text, cm, tm, font_dict, font_size, _fragments=fragments):
            if not text or not text.strip():
                return
            x = tm[4] * cm[0] + cm[4]
            y = tm[5] * cm[3] + cm[5]
            scale = abs(tm[3] * cm[3]) or 1.0
            font = str((font_dict or {}).get("/BaseFont", ""))
            _fragments.append(Fragment(x=float(x), y=float(y), size=float(font_size) * scale,
                                       bold="bold" in font.lower(), text=text.strip(),
                                       seq=len(_fragments)))

        try:
            page.extract_text(visitor_text=visitor)
        except Exception as exc:  # a damaged page must not abort the document
            log.warning("Could not extract page %d of %s: %s", page_index, path.name,
                        type(exc).__name__)
            continue
        height = float(page.mediabox.height) or 792.0
        fragments = [f for f in fragments if 0.06 * height <= f.y <= 0.935 * height]
        fragments.sort(key=lambda f: (-f.y, f.seq))
        current: list[Fragment] = []
        for frag in fragments:
            if current and abs(current[0].y - frag.y) > 2.0:
                lines.append(_make_line(page_index, current))
                current = []
            current.append(frag)
        if current:
            lines.append(_make_line(page_index, current))
    meta = reader.metadata or {}
    return lines, {"title": clean_text(getattr(meta, "title", "") or "")}


def _make_line(page: int, fragments: list[Fragment]) -> Line:
    ordered = sorted(fragments, key=lambda f: (f.x, f.seq))
    bullet = False
    if len(ordered) > 1 and _is_bullet_fragment(ordered[0].text):
        ordered, bullet = ordered[1:], True
    return Line(page=page, y=max(f.y for f in fragments), fragments=ordered, bullet=bullet)


def _same_columns(xs: Sequence[float], columns: Sequence[float], tolerance: float = 3.0) -> bool:
    return all(any(abs(x - c) <= tolerance for c in columns) for x in xs)


def _column_index(x: float, columns: Sequence[float]) -> int:
    return min(range(len(columns)), key=lambda i: abs(columns[i] - x))


def _find_tables(lines: list[Line]) -> dict[int, tuple[int, list[float]]]:
    """Locate table blocks.  Returns {start_index: (end_index_exclusive, columns)}.

    A table is a run of lines on one page whose cells start at the same set of
    x positions, with at least three multi-cell lines.
    """
    tables: dict[int, tuple[int, list[float]]] = {}
    index = 0
    while index < len(lines):
        cells = lines[index].cells()
        if len(cells) < 2 or lines[index].bullet:
            index += 1
            continue
        columns = [x for x, _ in cells]
        end, multi = index + 1, 1
        while end < len(lines) and lines[end].page == lines[index].page and not lines[end].bullet:
            xs = [x for x, _ in lines[end].cells()]
            if not _same_columns(xs, columns):
                # a wider header-less first row may have missed a column: allow growth
                if len(xs) > len(columns) and _same_columns(columns, xs):
                    columns = xs
                else:
                    break
            gap = lines[end - 1].y - lines[end].y
            if len(xs) == 1 and gap > 1.6 * max(lines[end].size, 6.0):
                break            # a lone cell far below is not part of the table
            multi += len(xs) >= 2
            end += 1
        if multi >= 3 or (multi >= 2 and lines[index].all_bold):   # header + one row
            tables[index] = (end, columns)
            index = end
        else:
            index += 1
    return tables


def _table_rows(lines: list[Line], columns: list[float]) -> tuple[list[list[str]], bool, list[int]]:
    """Merge wrapped lines into rows.  Returns (rows, has_header, row_pages)."""
    rows: list[list[str]] = []
    bold_rows: list[bool] = []
    pages: list[int] = []
    previous: Line | None = None
    for line in lines:
        gap = (previous.y - line.y) if previous is not None else 1e9
        continuation = previous is not None and gap <= 1.6 * max(line.size, 6.0)
        if not continuation:
            rows.append([""] * len(columns))
            bold_rows.append(True)
            pages.append(line.page)
        for x, text in line.cells():
            col = _column_index(x, columns)
            rows[-1][col] = clean_text(f"{rows[-1][col]} {text}")
        bold_rows[-1] = bold_rows[-1] and line.all_bold
        previous = line
    has_header = len(rows) > 1 and bold_rows[0] and not bold_rows[1]
    return rows, has_header, pages


def _looks_like_abbreviation_table(rows: list[list[str]], n_cols: int) -> bool:
    if n_cols not in (2, 4) or len(rows) < 4:
        return False
    short = sum(1 for row in rows if row[0] and len(row[0]) <= 12 and " " not in row[0].strip("/ "))
    return short / len(rows) >= 0.8


def _section_alias_source(section: str) -> str:
    text = re.sub(r"\([^)]*\)", " ", section)
    text = re.sub(r"^(part|section|chapter)\s+\w+\s*[-:–]\s*", "", text.strip(), flags=re.I)
    return re.sub(r"^\d+(\.\d+)*\s+", "", text.strip())


def parse_pdf(path: Path) -> ParsedDocument:
    lines, meta = extract_pdf_lines(path)
    if not lines:
        raise DataValidationError(f"No extractable text in {path.name}")
    body_size = Counter(round(f.size, 1) for line in lines for f in line.fragments).most_common(1)[0][0]
    title = meta["title"]
    if not title or len(title) < 6 or title.lower().endswith((".pdf", ".docx", ".doc")):
        first_page = [l for l in lines if l.page == lines[0].page]
        biggest = max(l.size for l in first_page)
        heading = " ".join(l.text for l in first_page if l.size >= biggest - 0.5)
        title = heading if biggest > body_size * 1.3 and 6 <= len(heading) <= 120 else \
            clean_text(path.stem.replace("_", " "))
    doc = ParsedDocument(title=title, source_file=path.name)

    tables = _find_tables(lines)
    part, section = "", ""
    buffer: list[str] = []
    buffer_page: int | None = None
    paragraph: list[Line] = []

    def current_section() -> str:
        return section or part or "Overview"

    def flush_paragraph() -> None:
        nonlocal buffer_page
        if not paragraph:
            return
        text = clean_text(" ".join(l.text for l in paragraph))
        first = paragraph[0]
        if text and "....." not in text:
            if buffer_page is None:
                buffer_page = first.page
            buffer.append(("• " if first.bullet else "") + text)
            _maybe_bullet_term(doc, paragraph, current_section())
            if len(paragraph) == 1:
                match = _ACRONYM_LINE_RE.match(text)
                if match and sum(c.isupper() for c in match.group(1)) >= 2:
                    doc.terms.append(TermRecord(
                        term=match.group(1), definition=match.group(2).strip(),
                        category="Abbreviation", page_number=first.page,
                        aliases=term_aliases(match.group(1), [match.group(2)])))
        paragraph.clear()

    def flush_chunk(force: bool = True) -> None:
        nonlocal buffer_page
        flush_paragraph()
        if not buffer or (not force and sum(len(b) for b in buffer) < CHUNK_TARGET_CHARS):
            return
        content = "\n".join(buffer)
        if len(re.sub(r"[^A-Za-z]", "", content)) >= 120 and not _SKIP_SECTIONS.match(current_section()):
            doc.chunks.append(ChunkRecord(section=current_section(), content=content,
                                          page_number=buffer_page))
        buffer.clear()
        buffer_page = None

    index = 0
    previous: Line | None = None
    while index < len(lines):
        if index in tables:
            flush_paragraph()
            end, columns = tables[index]
            rows, has_header, pages = _table_rows(lines[index:end], columns)
            header = rows[0] if has_header else None
            body = rows[1:] if has_header else rows
            body_pages = pages[1:] if has_header else pages
            if header and len(columns) == 2 and header[0].strip().lower() in _GLOSSARY_HEADERS:
                for row, page in zip(body, body_pages):
                    if row[0] and row[1]:
                        doc.terms.append(TermRecord(term=row[0], definition=row[1],
                                                    category=current_section(), page_number=page,
                                                    aliases=term_aliases(row[0])))
            elif header is None and _looks_like_abbreviation_table(body, len(columns)):
                for row, page in zip(body, body_pages):
                    for col in range(0, len(columns), 2):
                        if row[col] and row[col + 1]:
                            doc.terms.append(TermRecord(
                                term=row[col], definition=row[col + 1], category="Abbreviation",
                                page_number=page, aliases=term_aliases(row[col], [row[col + 1]])))
            else:
                if buffer_page is None:
                    buffer_page = lines[index].page
                if header:
                    buffer.append(" | ".join(header))
                buffer.extend(" | ".join(cell for cell in row if cell) for row in body)
            previous = lines[end - 1]
            index = end
            continue

        line = lines[index]
        text = line.text
        is_heading = (line.all_bold and not line.bullet and len(line.cells()) == 1
                      and 3 <= len(text) <= 90 and not text.endswith((":", ".", ",", "]"))
                      and (text[0].isupper() or text[0].isdigit())
                      and len(text.split()) <= 10)
        if is_heading:
            flush_chunk()
            if line.size >= body_size * 1.6:
                part, section = text, ""
            else:
                section = text
        else:
            gap = (previous.y - line.y) if previous is not None and previous.page == line.page else 1e9
            if line.bullet or gap > 1.6 * max(line.size, 6.0):
                flush_paragraph()
                flush_chunk(force=False)
            paragraph.append(line)
        previous = line
        index += 1
    flush_chunk()
    return doc


def _maybe_bullet_term(doc: ParsedDocument, paragraph: list[Line], section: str) -> None:
    """'• Term (Expansion): definition ...' with a bold lead-in becomes a term."""
    if not paragraph[0].bullet:
        return
    fragments = [f for line in paragraph for f in sorted(line.fragments, key=lambda f: (f.x, f.seq))]
    lead: list[str] = []
    rest_start = 0
    for position, frag in enumerate(fragments):
        if not frag.bold:
            break
        lead.append(frag.text)
        rest_start = position + 1
    term = clean_text(" ".join(lead))
    if not term.endswith(":") or rest_start >= len(fragments):
        return
    term = term[:-1].strip()
    definition = clean_text(" ".join(f.text for f in fragments[rest_start:]))
    if 1 <= len(term.split()) <= 9 and len(definition) >= 25:
        doc.terms.append(TermRecord(term=term, definition=definition, category=section,
                                    page_number=paragraph[0].page, aliases=term_aliases(term)))


_MD_TERM_RE = re.compile(r"^\*\*(.+?)\*\*\s*[:—-]\s*(.+)$")


def parse_text_document(path: Path) -> ParsedDocument:
    """Markdown / plain-text reference documents.

    ``# Title``, ``## Section`` and ``**Term**: definition`` lines are recognised;
    everything else becomes searchable chunks.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    doc = ParsedDocument(title=clean_text(path.stem.replace("_", " ")), source_file=path.name)
    section, buffer = "Overview", []

    def flush() -> None:
        content = "\n".join(buffer).strip()
        if len(content) >= 80:
            for start in range(0, len(content), CHUNK_TARGET_CHARS):
                doc.chunks.append(ChunkRecord(section=section,
                                              content=content[start:start + CHUNK_TARGET_CHARS],
                                              page_number=None))
        buffer.clear()

    for raw_line in raw.splitlines():
        line = clean_text(raw_line)
        if not line:
            continue
        if line.startswith("# "):
            doc.title = line[2:].strip()
        elif line.startswith("#"):
            flush()
            section = line.lstrip("#").strip()
        else:
            match = _MD_TERM_RE.match(line)
            if match:
                doc.terms.append(TermRecord(term=match.group(1).strip(),
                                            definition=match.group(2).strip(), category=section,
                                            page_number=None, aliases=term_aliases(match.group(1))))
            buffer.append(line.replace("**", ""))
    flush()
    return doc


def parse_reference_document(path: Path) -> ParsedDocument:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return parse_pdf(path)
    if suffix in {".md", ".txt"}:
        return parse_text_document(path)
    raise DataValidationError(f"Unsupported reference document type: {path.name}")


# --------------------------------------------------------------------------- #
# Foundational collection ingestion
# --------------------------------------------------------------------------- #
SUPPORTED_DOC_SUFFIXES = {".pdf", ".md", ".txt"}
FOUNDATION_SOURCE = "foundation"


def document_to_rows(doc: ParsedDocument) -> tuple[list[dict], list[dict]]:
    """Convert a parsed document into CyberTerm and CyberDocument node rows."""
    now = utc_now_iso()
    doc_slug = slugify(Path(doc.source_file).stem, 40)
    term_rows: dict[str, dict] = {}
    for term in doc.terms:
        node_id = f"term:{doc_slug}:{slugify(term.term)}"
        if node_id in term_rows:        # same term twice in one document: merge
            existing = term_rows[node_id]
            if term.definition not in existing["definition"]:
                existing["definition"] += " " + term.definition
            existing["aliases"] = dedupe(existing["aliases"] + term.aliases)
            continue
        term_rows[node_id] = {
            "id": node_id, "term": term.term, "definition": clean_text(term.definition, 2000),
            "category": term.category, "examples": _examples_from(term.definition),
            "aliases": term.aliases, "source": doc.title, "source_file": doc.source_file,
            "page_number": term.page_number, "synced_at": now,
        }
    doc_rows = []
    for index, chunk in enumerate(doc.chunks):
        doc_rows.append({
            "id": f"doc:{doc_slug}:{index:04d}", "title": f"{doc.title} - {chunk.section}",
            "section": chunk.section, "content": chunk.content, "source": doc.title,
            "source_file": doc.source_file, "page_number": chunk.page_number,
            "chunk_index": index, "aliases": term_aliases(_section_alias_source(chunk.section)),
            "synced_at": now,
        })
    for row in list(term_rows.values()) + doc_rows:
        row["content_hash"] = content_hash({k: v for k, v in row.items() if k != "synced_at"})
    return list(term_rows.values()), doc_rows


def _examples_from(definition: str) -> list[str]:
    """Examples that the source itself lists ('Examples: AES, DES' / '(e.g. ...)')."""
    found: list[str] = []
    for match in re.finditer(r"(?:Examples?:|e\.g\.,?)\s*([^.;)]+)", definition):
        found += [clean_text(item) for item in re.split(r",| and ", match.group(1)) if item.strip()]
    return dedupe(found)[:10]


class FoundationIngestor:
    """Indexes the approved reference documents into Neo4j (idempotent)."""

    def __init__(self, db, embedder: EmbeddingClient, settings: Settings):
        self.db, self.embedder, self.settings = db, embedder, settings

    def list_documents(self) -> list[Path]:
        folder = Path(self.settings.reference_docs_dir)
        if not folder.is_dir():
            return []
        return sorted(p for p in folder.iterdir()
                      if p.is_file() and p.suffix.lower() in SUPPORTED_DOC_SUFFIXES)

    def ingest_all(self, force: bool = False) -> dict:
        """Ingest every document; a failing document never affects the others."""
        started = utc_now_iso()
        self.db.save_sync_state(FOUNDATION_SOURCE, status="running", last_attempt_at=started)
        summary: dict[str, Any] = {"documents": [], "terms": 0, "chunks": 0, "errors": []}
        state = self.db.get_sync_state(FOUNDATION_SOURCE)
        hashes: dict[str, str] = json.loads(state.get("document_hashes") or "{}")
        for path in self.list_documents():
            try:
                file_hash = content_hash([self.embedder.signature,
                                          hashlib.sha256(path.read_bytes()).hexdigest()])
                if not force and hashes.get(path.name) == file_hash:
                    summary["documents"].append({"file": path.name, "status": "unchanged"})
                    continue
                result = self.ingest_document(path)
                hashes[path.name] = file_hash
                summary["documents"].append({"file": path.name, "status": "indexed", **result})
                summary["terms"] += result["terms"]
                summary["chunks"] += result["chunks"]
            except Exception as exc:
                log.exception("Failed to ingest reference document %s", path.name)
                summary["errors"].append(f"{path.name}: {type(exc).__name__}: {exc}")
        finished = utc_now_iso()
        fields = {"last_attempt_at": finished, "document_hashes": json.dumps(hashes),
                  "details": json.dumps(summary["documents"])[:4000]}
        if summary["errors"]:
            self.db.save_sync_state(FOUNDATION_SOURCE, status="failed",
                                    last_error="; ".join(summary["errors"])[:1000], **fields)
        else:
            self.db.save_sync_state(FOUNDATION_SOURCE, status="success", last_error=None,
                                    last_success_at=finished, **fields)
        return summary

    def ingest_document(self, path: Path) -> dict:
        doc = parse_reference_document(path)
        term_rows, doc_rows = document_to_rows(doc)
        if not term_rows and not doc_rows:
            raise DataValidationError(f"{path.name} produced no terms or text chunks")
        attach_embeddings(self.db, self.embedder, LABEL_TERM, term_rows, EMBEDDING_TEXT[LABEL_TERM])
        attach_embeddings(self.db, self.embedder, LABEL_DOC, doc_rows, EMBEDDING_TEXT[LABEL_DOC])
        self.db.upsert_nodes(LABEL_TERM, term_rows)
        self.db.upsert_nodes(LABEL_DOC, doc_rows)
        removed = self.db.delete_stale_foundation(
            doc.source_file, [r["id"] for r in term_rows] + [r["id"] for r in doc_rows])
        log.info("Indexed %s: %d terms, %d chunks (%d stale removed)", path.name,
                 len(term_rows), len(doc_rows), removed)
        return {"title": doc.title, "terms": len(term_rows), "chunks": len(doc_rows),
                "removed": removed}


# --------------------------------------------------------------------------- #
# Synchronisation result + shared flow for the MITRE snapshot sources
# --------------------------------------------------------------------------- #
@dataclass
class SyncResult:
    source: str
    status: str                      # "success" | "unchanged" | "failed"
    records: int = 0
    changed: int = 0
    error: str | None = None
    details: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in {"success", "unchanged"}

    def as_dict(self) -> dict:
        return {"source": self.source, "status": self.status, "records": self.records,
                "changed": self.changed, "error": self.error, "details": self.details}


def safe_error(exc: BaseException) -> str:
    """Short error text for status endpoints (no secrets, bounded length)."""
    return clean_text(f"{type(exc).__name__}: {exc}", 500)


class SnapshotUpdater:
    """Download -> validate -> upsert -> rebuild relationships -> checkpoint.

    Used by the CWE, CAPEC and ATT&CK updaters, whose official sources publish
    complete snapshots.  The stored checkpoint (content hash + timestamps) is only
    written after every database write of the run has succeeded, so a failed run
    is simply repeated next time and never damages existing records.
    """

    source: str = ""
    label: str = ""
    rel_types: tuple[str, ...] = ()
    id_pattern: re.Pattern = re.compile(r".+")

    def __init__(self, db, embedder: EmbeddingClient, settings: Settings,
                 http_client: httpx.Client | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.db, self.embedder, self.settings = db, embedder, settings
        self._client = http_client
        self._sleep = sleep

    # -- hooks ----------------------------------------------------------- #
    def urls(self) -> list[str]:
        raise NotImplementedError

    def parse(self, payloads: list[bytes]) -> tuple[list[dict], dict]:
        raise NotImplementedError

    def after_write(self) -> None:
        """Optional extra linking step once nodes and relationships are stored."""

    # -- flow ------------------------------------------------------------ #
    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = build_http_client(self.settings)
        return self._client

    def download(self) -> list[bytes]:
        return [http_get(self._http(), url, max_retries=self.settings.http_max_retries,
                         sleep=self._sleep).content for url in self.urls()]

    def validate(self, rows: list[dict], state: dict) -> None:
        if not rows:
            raise DataValidationError(f"{self.source}: the official source returned no records")
        ids = [row.get("id", "") for row in rows]
        bad = [i for i in ids if not self.id_pattern.match(str(i))]
        if bad:
            raise DataValidationError(f"{self.source}: invalid identifiers such as {bad[:3]}")
        if len(set(ids)) != len(ids):
            raise DataValidationError(f"{self.source}: duplicate identifiers in parsed data")
        previous = int(state.get("records") or 0)
        if previous and len(rows) < previous * 0.5:
            raise DataValidationError(
                f"{self.source}: only {len(rows)} records parsed but {previous} were stored "
                "by the last successful run; refusing a suspicious update")

    def sync(self, force: bool = False) -> SyncResult:
        started = utc_now_iso()
        sync_id = f"{self.source}:{started}"
        try:
            state = self.db.get_sync_state(self.source)
            self.db.save_sync_state(self.source, status="running", last_attempt_at=started)
            payloads = self.download()
            digest = content_hash([hashlib.sha256(p).hexdigest() for p in payloads])
            if not force and state.get("content_hash") == digest and state.get("last_success_at"):
                self.db.save_sync_state(self.source, status="success", last_error=None,
                                        last_checked_at=utc_now_iso())
                log.info("%s: official data unchanged since last sync", self.source)
                return SyncResult(self.source, "unchanged", records=int(state.get("records") or 0))
            rows, meta = self.parse(payloads)
            self.validate(rows, state)
            now = utc_now_iso()
            for row in rows:
                row["content_hash"] = content_hash(row)
            stored = self.db.get_property_map(self.label, [r["id"] for r in rows], "content_hash")
            embedded = attach_embeddings(self.db, self.embedder, self.label, rows,
                                         EMBEDDING_TEXT[self.label])
            to_write = [r for r in rows
                        if stored.get(r["id"]) != r["content_hash"] or "embedding" in r]
            for row in to_write:
                row["synced_at"] = now
            self.db.upsert_nodes(self.label, to_write)
            relationships = self.db.rebuild_relationships(self.rel_types, sync_id)
            self.after_write()
            finished = utc_now_iso()
            details = {**meta, "embedded": embedded, "relationships": relationships}
            self.db.save_sync_state(
                self.source, status="success", last_error=None, last_success_at=finished,
                last_checked_at=finished, content_hash=digest, records=len(rows),
                changed_records=len(to_write), details=json.dumps(details)[:4000])
            log.info("%s: synced %d records (%d new/changed)", self.source, len(rows), len(to_write))
            return SyncResult(self.source, "success", records=len(rows), changed=len(to_write),
                              details=details)
        except Exception as exc:  # report, never advance the checkpoint
            log.exception("%s synchronisation failed", self.source)
            error = safe_error(exc)
            try:
                self.db.save_sync_state(self.source, status="failed", last_error=error,
                                        last_failure_at=utc_now_iso())
            except Exception:
                log.error("%s: could not record the failure in Neo4j", self.source)
            return SyncResult(self.source, "failed", error=error)
