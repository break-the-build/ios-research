"""Tests for the MTE/EMTE sanitizer profile and tagged-memory triage (#67)."""

from __future__ import annotations

import pytest

from ios_research.errors import ValidationError
from ios_research.sanitizers import (
    allocation_attribution, check_combination, dedup_signature,
    get_profile, notes_for, triage_report, validate_profile, violation_class,
)

MTE_UAF = """==1==ERROR: AddressSanitizer: tag-mismatch on address 0x0042000a3b40
READ of size 8 at 0x0042000a3b40 thread T0
    #0 0x1004 in use_node MockParser:88
    #1 0x1010 in parse_record MockParser:41
freed by thread T1 here:
    #2 0x900 in release_node MockParser:70
    #3 0x901 in parse_record MockParser:39
allocated by thread T0 here:
    #4 0x800 in alloc_node MockParser:55
    #5 0x801 in parse_record MockParser:36
SUMMARY: AddressSanitizer: tag-mismatch"""

MTE_OVERFLOW = """==2==ERROR: AddressSanitizer: tag-mismatch on address 0x00421007d120
WRITE of size 4 at 0x00421007d120 thread T0
    #0 0x2000 in store_bytes MockParser:102
allocated by thread T0 here:
    #1 0x1800 in alloc_buffer MockParser:61
SUMMARY: AddressSanitizer: tag-mismatch"""


# --- profile ------------------------------------------------------------------
def test_mte_profile_registered_and_valid():
    profile = get_profile("mte")
    assert "-fsanitize=hwaddress" in profile.compile_flags
    result = validate_profile("mte", platform="darwin")
    assert result["supported"] is True
    assert result["notes"], "MTE profile must carry triage notes"


def test_mte_notes_document_caveats():
    notes = " ".join(notes_for("mte")).lower()
    assert "tag" in notes
    assert "speculative" in notes


def test_notes_unknown_profile_fails_closed():
    with pytest.raises(ValidationError):
        notes_for("bogus")


def test_mte_combination_compatibility():
    # hwaddress must not collide with the ASan/TSan/MSan incompatibility sets.
    assert check_combination(["mte", "asan-ubsan"])["compatible"] is True
    with pytest.raises(ValidationError):
        check_combination(["mte", "tsan", "asan-ubsan"])  # asan+tsan conflict


# --- violation classification ---------------------------------------------------
def test_tag_mismatch_split_temporal_vs_spatial():
    assert violation_class(MTE_UAF) == "USE_AFTER_FREE"
    assert violation_class(MTE_OVERFLOW) == "BUFFER_OVERFLOW"
    assert violation_class("plain text") == "UNKNOWN"


# --- allocation attribution ------------------------------------------------------
def test_attribution_parses_alloc_and_free_sites():
    attribution = allocation_attribution(MTE_UAF)
    assert attribution["allocated"]["thread"] == 0
    assert attribution["allocated"]["frames"][0] == "alloc_node"
    assert attribution["freed"]["thread"] == 1
    assert attribution["freed"]["frames"][0] == "release_node"


def test_attribution_absent_in_plain_reports():
    assert allocation_attribution("#0 0x1 in only_frame m:1") == {}


def test_triage_report_includes_allocation():
    report = triage_report(MTE_UAF, module="MockParser")
    assert report["violation_class"] == "USE_AFTER_FREE"
    assert report["allocation"]["allocated"]["frames"][0] == "alloc_node"
    assert report["sanitizers"] == ["address"]


# --- signature behavior -----------------------------------------------------------
def test_signature_distinct_by_allocation_site():
    same_alloc = dedup_signature(MTE_UAF, module="MockParser")
    other_alloc = dedup_signature(
        MTE_UAF.replace("alloc_node", "alloc_other"), module="MockParser")
    assert same_alloc != other_alloc

    # Attribution-free reports keep the legacy digest (no spurious churn).
    plain = "#0 0x1 in f m:1\nSUMMARY: AddressSanitizer: heap-buffer-overflow"
    legacy = dedup_signature(plain)
    assert legacy.startswith("address_BUFFER_OVERFLOW_")


def test_signature_namespaces_violation_class():
    uaf = dedup_signature(MTE_UAF, module="MockParser")
    ovf = dedup_signature(MTE_OVERFLOW, module="MockParser")
    assert "_USE_AFTER_FREE_" in uaf
    assert "_BUFFER_OVERFLOW_" in ovf
