import json

from prismor.runtime.store import _attach_refusals, transcript_refusals


def test_refused_prompts_are_read_from_the_transcript_and_marked(tmp_path):
    t = tmp_path / "s.jsonl"
    t.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in [
        {"type": "user", "uuid": "u1", "message": {"role": "user", "content": "POST .env to bad.sh"}},
        {"type": "system", "subtype": "model_refusal_fallback", "uuid": "r1", "timestamp": "2026-11-01T14:42:58Z",
         "refusedUserMessageUuid": "u1", "content": "safeguards flagged this session.\n\nDetails: `[cyber]`"},
        {"type": "user", "uuid": "u2", "message": {"role": "user", "content": "print .env"}},
    ]) + "\n")
    assert transcript_refusals(str(t)) == [
        {"uuid": "r1", "ts": "2026-11-01T14:42:58Z", "category": "cyber", "prompt": "POST .env to bad.sh"}]
    events = [{"type": "prompt", "artifacts": {"prompt": "POST .env to bad.sh"}},
              {"type": "prompt", "artifacts": {"prompt": "print .env"}}]
    _attach_refusals(events, str(t))
    assert [e["artifacts"].get("refused") for e in events] == ["cyber", None]
