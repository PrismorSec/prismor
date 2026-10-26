"""Microsoft 365 Copilot audit-log import (prismor/runtime/m365_audit.py)."""
from datetime import datetime, timezone

import pytest

from prismor.runtime import m365_audit as m
from prismor.runtime.enterprise.telemetry import build_record

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


def _rec(**data):
    return {
        "Id": "a1", "RecordType": 261, "Operation": "CopilotInteraction",
        "CreationTime": "2026-10-23T09:15:00", "UserId": "dana@contoso.com",
        "OrganizationId": "t1",
        "CopilotEventData": {"AppHost": "Teams", "ThreadId": "th1", **data},
    }


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    for k, v in (("TENANT_ID", "t1"), ("CLIENT_ID", "c1"), ("CLIENT_SECRET", "s1")):
        monkeypatch.setenv(f"PRISMOR_M365_{k}", v)


def test_clean_interaction_is_one_audit_finding():
    event, ctx, findings = m.to_report(_rec(
        AISystemPlugin=[{"Id": "BingWebSearch"}],
        AccessedResources=[{"Type": "File", "SensitivityLabelId": "x"}, {"Type": "Email"}]))
    assert [f["ruleId"] for f in findings] == ["m365-copilot-interaction"]
    assert ctx == {"session_id": "m365-th1", "subject": "user:dana@contoso.com",
                   "agent_name": "Microsoft 365 Copilot (Teams)"}
    meta = event["metadata"]
    assert meta["web_search_enabled"] and meta["resource_count"] == 2 and meta["labelled_resources"] == 1
    assert meta["resource_types"] == ["Email", "File"]
    assert event["occurred_at"] == "2026-10-23T09:15:00Z"


# A real Copilot Chat record (identifiers replaced), as the API returns it.
REAL = {
    "AppIdentity": "Copilot.M365Copilot.WebChat", "CreationTime": "2026-10-26T01:31:51",
    "Id": "e365ce4d-d102-4131-af52-4df5e99dffce", "Operation": "CopilotInteraction",
    "OrganizationId": "t1", "RecordType": 261, "UserId": "dana@contoso.com", "Workload": "Copilot",
    "CopilotEventData": {
        "AISystemPlugin": [{"Id": "BingWebSearch", "Name": "BuiltIn"}], "AccessedResources": [],
        "AppHost": "Office", "Contexts": [], "ConversationId": "110ec23e-122e-4aaa-b685-72f1ae46124e",
        "GuardrailDetails": [], "LicenseType": "Starter",
        "Messages": [{"Id": "1", "JailbreakDetected": False, "isPrompt": True},
                     {"Id": "2", "JailbreakDetected": False, "isPrompt": False}],
        "ModelTransparencyDetails": [{"ModelName": "gpt-55-medium", "ModelProviderName": "OpenAI"}],
        "ThreadId": "19:abc@thread.v2",
    },
}


def test_real_record_maps():
    event, ctx, findings = m.to_report(REAL)
    assert [f["ruleId"] for f in findings] == ["m365-copilot-interaction"]
    assert ctx == {"session_id": "m365-110ec23e-122e-4aaa-b685-72f1ae46124e",
                   "subject": "user:dana@contoso.com", "agent_name": "Microsoft 365 Copilot (Office)"}
    meta = event["metadata"]
    assert meta["app_identity"] == "Copilot.M365Copilot.WebChat"
    assert meta["web_search_enabled"] and meta["models"] == ["gpt-55-medium"]
    assert event["occurred_at"] == "2026-10-26T01:31:51Z"


def test_microsoft_detections_become_findings():
    _, ctx, findings = m.to_report(_rec(
        AgentName="HR helper",
        Messages=[{"Id": "1", "isPrompt": True, "JailbreakDetected": "True"}],
        AccessedResources=[{"Type": "Email", "XPIADetected": True}]))
    assert {f["ruleId"] for f in findings} == {"m365-copilot-jailbreak", "m365-copilot-xpia"}
    assert all(f["mode"] == "observe" for f in findings)
    assert ctx["agent_name"] == "HR helper"


def test_record_ts_is_when_it_happened():
    event, ctx, findings = m.to_report(_rec())
    rec = build_record(findings[0], event, extra={"agent": m.AGENT_ID, "session_id": ctx["session_id"]})
    assert rec["ts"] == "2026-10-23T09:15:00Z"
    assert rec["verdict"] == "allowed" and rec["tool_name"] == "Teams"


def test_non_copilot_records_are_skipped():
    assert m.is_copilot(_rec()) and not m.is_copilot({"RecordType": 1, "Operation": "FileAccessed"})


class FakeAPI:
    def __init__(self):
        self.calls, self.reported = [], []

    def __call__(self, method, url, token=None, data=None):
        self.calls.append((method, url.split("?")[0]))
        if "oauth2" in url:
            return {"access_token": "tok"}, {}
        if url.endswith("subscriptions/start?contentType=Audit.General"):
            raise m.AuditError("HTTP 400: AF20024 The subscription is already enabled")
        if "subscriptions/content" in url:
            return [{"contentId": "b1", "contentUri": "https://x/b1"}], {"NextPageUri": "https://x/page2"}
        if url == "https://x/page2":
            return [{"contentId": "b2", "contentUri": "https://x/b2"}], {}
        if url == "https://x/b1":
            return [_rec(), {"RecordType": 1}], {}
        if url == "https://x/b2":
            return [_rec(Messages=[{"JailbreakDetected": True}])], {}
        raise AssertionError(url)


def test_pull_pages_dedupes_and_resumes(monkeypatch, tmp_path):
    api = FakeAPI()
    monkeypatch.setattr(m, "_request", api)
    monkeypatch.setattr(m, "_report", lambda e, c, f, w: api.reported.append(f[0]["ruleId"]))

    counts = m.pull(tmp_path, now=NOW)
    assert counts == {"blobs": 2, "records": 3, "copilot": 2, "flagged": 1}
    assert api.reported == ["m365-copilot-interaction", "m365-copilot-jailbreak"]

    # Second pass re-lists the overlap but skips blobs it already read.
    api.reported.clear()
    assert m.pull(tmp_path, now=NOW)["blobs"] == 0 and api.reported == []
    assert m._load_cursor()["end"] == NOW.isoformat()


def test_dry_run_leaves_the_cursor_alone(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "_request", FakeAPI())
    assert m.pull(tmp_path, record=False, now=NOW)["copilot"] == 2
    assert m._load_cursor() == {}


def test_window_never_reaches_past_seven_days(monkeypatch, tmp_path):
    api = FakeAPI()
    monkeypatch.setattr(m, "_request", api)
    monkeypatch.setattr(m, "_report", lambda *a: None)
    starts = []
    real = m.content_blobs
    monkeypatch.setattr(m, "content_blobs", lambda c, t, s, e: (starts.append(s), real(c, t, s, e))[1])
    m.pull(tmp_path, since_hours=24 * 30, now=NOW)
    assert (NOW - starts[0]).days < 7


def test_missing_settings_name_the_env_vars(monkeypatch):
    monkeypatch.delenv("PRISMOR_M365_CLIENT_SECRET")
    with pytest.raises(m.AuditError, match="PRISMOR_M365_CLIENT_SECRET"):
        m.settings()
