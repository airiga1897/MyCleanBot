from dataclasses import dataclass

from core.services.matcher import (
    TextCandidate,
    decoded_url_variants,
    extract_candidates,
    find_matches,
    is_status_command,
    normalize_text,
)


@dataclass
class MessageEntityUrl:
    offset: int
    length: int


@dataclass
class MessageEntityTextUrl:
    offset: int
    length: int
    url: str


def test_normalize_text_collapses_whitespace_and_case() -> None:
    assert normalize_text("  ЗаПреТ\n\t Текст  ") == "запрет текст"


def test_matches_body_substring() -> None:
    matches = find_matches([TextCandidate("body", "До ЗАПРЕТ после")], [(7, "запрет")])
    assert [(item.rule_id, item.source) for item in matches] == [(7, "body")]


def test_extracts_visible_and_hidden_urls() -> None:
    text = "ссылка пример"
    entities = [
        MessageEntityUrl(0, 6),
        MessageEntityTextUrl(7, 6, "https://example.test/secret"),
    ]
    candidates = extract_candidates(text, entities)
    values = {item.value for item in candidates if item.source == "link_target"}
    assert "ссылка" in values
    assert "https://example.test/secret" in values


def test_url_offsets_follow_telegram_utf16_units() -> None:
    text = "😀 https://example.test"
    # Emoji occupies two UTF-16 code units, then one unit for the space.
    entity = MessageEntityUrl(3, 20)
    candidates = extract_candidates(text, [entity])
    assert any(item.value == "https://example.test" for item in candidates)


def test_decodes_percent_encoding_and_idn_without_network() -> None:
    variants = decoded_url_variants("https://xn--e1afmkfd.xn--p1ai/%D1%82%D0%B5%D1%81%D1%82")
    assert any("пример.рф" in item for item in variants)
    assert any("/тест" in item for item in variants)


def test_malformed_url_is_still_returned() -> None:
    assert "http://[broken" in decoded_url_variants("http://[broken")


def test_status_command_only_in_saved_messages() -> None:
    assert is_status_command(" /MC_STATUS ", True)
    assert not is_status_command("/mc_status", False)
    assert not is_status_command("/mc_pause", True)
