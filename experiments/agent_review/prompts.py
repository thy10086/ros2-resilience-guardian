"""Use the reviewed, original ROS role instructions; never interpolate evidence."""
from hashlib import sha256
from pathlib import Path

PROMPT_VERSION = "guardian-agent-review-prompts/v2"
ROLES = ("goals", "planner", "worker", "reviewer")
PROMPT_PATH = Path(__file__).resolve().parents[2] / "docs/artex_ros2_agent_prompts.md"


def role_prompt(role):
    if role not in ROLES:
        raise ValueError("unknown role")
    text = PROMPT_PATH.read_text(encoding="utf-8")
    common = text.split("## 固定平台约束（所有角色）", 1)[1].split("\n## ", 1)[0]
    body = text.split(f"## `{role}`", 1)[1].split("\n## ", 1)[0]
    instruction = common + "\n" + body
    return {"version": PROMPT_VERSION, "sha256": sha256(instruction.encode()).hexdigest(),
            "system": instruction}
