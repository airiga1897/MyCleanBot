from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class TextCandidate:
    source: str
    value: str


@dataclass(frozen=True)
class Match:
    rule_id: int
    source: str


def normalize_text(value: str) -> str:
    return _WHITESPACE.sub(" ", value.strip()).casefold()


def decoded_url_variants(url: str) -> set[str]:
    variants = {url, unquote(url)}
    try:
        parts = urlsplit(unquote(url))
        host = parts.hostname or ""
        unicode_host = host.encode("ascii").decode("idna") if host else host
        if unicode_host and unicode_host != host:
            netloc = unicode_host
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
            variants.add(
                urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
            )
    except (UnicodeError, ValueError):
        pass
    return variants


def extract_candidates(text: str, entities: list[Any] | None) -> list[TextCandidate]:
    candidates = [TextCandidate("body", text)] if text else []
    for entity in entities or []:
        entity_name = entity.__class__.__name__
        if entity_name == "MessageEntityUrl":
            encoded = text.encode("utf-16-le")
            visible_url = encoded[entity.offset * 2 : (entity.offset + entity.length) * 2].decode(
                "utf-16-le", errors="replace"
            )
            candidates.extend(
                TextCandidate("link_target", item) for item in decoded_url_variants(visible_url)
            )
        elif entity_name == "MessageEntityTextUrl":
            target = str(entity.url)
            candidates.extend(
                TextCandidate("link_target", item) for item in decoded_url_variants(target)
            )
    return candidates


def find_matches(
    candidates: list[TextCandidate], normalized_rules: list[tuple[int, str]]
) -> list[Match]:
    found: dict[tuple[int, str], Match] = {}
    for candidate in candidates:
        normalized_candidate = normalize_text(candidate.value)
        for rule_id, phrase in normalized_rules:
            if phrase and phrase in normalized_candidate:
                found[(rule_id, candidate.source)] = Match(rule_id, candidate.source)
    return list(found.values())


def is_status_command(text: str, is_saved_messages: bool) -> bool:
    return is_saved_messages and normalize_text(text) == "/mc_status"
