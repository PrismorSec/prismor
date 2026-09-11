from prismor.runtime.store import _attach_task_durations


def _note(task_id, tool_use_id, ts):
    prompt = f"<task-notification>\n<task-id>{task_id}</task-id>\n"
    if tool_use_id:
        prompt += f"<tool-use-id>{tool_use_id}</tool-use-id>\n"
    prompt += "<summary>done</summary>\n</task-notification>"
    return {"_tsRaw": ts, "artifacts": {"prompt": prompt}}


CALLS = {"toolu_1": {"ts": "2026-09-10T16:18:03+00:00", "tool": "Bash", "detail": "aws s3 sync a b"}}


def test_duration_and_launching_call_come_from_the_tool_use_id():
    events = [_note("b1", "toolu_1", "2026-09-10T16:33:11+00:00")]
    _attach_task_durations(events, CALLS)
    artifacts = events[0]["artifacts"]
    assert artifacts["task_took"] == "15m 8s"
    assert artifacts["task_launched_by"] == "Bash - aws s3 sync a b"


def test_a_monitor_is_timed_from_its_own_first_event():
    # Newest first, the order the trail arrives in.
    events = [_note("b2", "", "2026-09-10T16:40:00+00:00"),
              _note("b2", "", "2026-09-10T16:33:00+00:00")]
    _attach_task_durations(events, CALLS)
    assert events[1]["artifacts"].get("task_took") is None  # nothing to measure from yet
    assert events[0]["artifacts"]["task_took"] == "+7m 0s"
    assert "Monitor" in events[0]["artifacts"]["task_launched_by"]


def test_an_unseen_launch_is_named_not_guessed():
    events = [_note("b3", "toolu_gone", "2026-09-10T16:33:11+00:00")]
    _attach_task_durations(events, CALLS)
    assert "task_took" not in events[0]["artifacts"]
    assert "toolu_gone" in events[0]["artifacts"]["task_launched_by"]


class _FakeRule:
    id = "dos-resource-exhaustion"
    raw_patterns = [r"yes\s*\|"]

    def matched_pattern(self, value):
        import re
        return self.raw_patterns[0] if re.search(self.raw_patterns[0], value) else None


def test_blocked_row_quotes_the_pattern_that_fired(monkeypatch):
    from prismor.runtime import policy_engine, store

    monkeypatch.setattr(policy_engine, "PolicyEngine",
                        lambda **kw: type("E", (), {"rules": [_FakeRule()]})())
    events = [{
        "verdict": "blocked",
        # The stored rule id keeps the session prefix and event index around it.
        "policy": {"ruleId": "abc:dos-resource-exhaustion-136", "evidence": "truncated..."},
        "artifacts": {"command": "aws ec2 describe-images | yes | head"},
    }]
    store._attach_matched_patterns(events, None)
    assert events[0]["policy"]["pattern"] == r"yes\s*\|"
    assert events[0]["policy"]["matched"] == "yes |"
