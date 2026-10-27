"""Use the reviewed, original ROS role instructions; never interpolate evidence."""
from hashlib import sha256
from pathlib import Path

PROMPT_VERSION = "guardian-agent-review-prompts/v3"
ROLES = ("goals", "planner", "worker", "reviewer")
PROMPT_PATH = Path(__file__).resolve().parents[2] / "docs/artex_ros2_agent_prompts.md"


def role_prompt(role):
    if role not in ROLES:
        raise ValueError("unknown role")
    text = PROMPT_PATH.read_text(encoding="utf-8")
    common = text.split("## 固定平台约束（所有角色）", 1)[1].split("\n## ", 1)[0]
    body = text.split(f"## `{role}`", 1)[1].split("\n## ", 1)[0]
    instruction = common + "\n" + body
    instruction += ("\n证据按风险和类型选择；evidence_selection 列出本次可见ID，"
        "没有额外补读工具。goals/planner 只能引用可见集合，不推断未选证据内容。")
    if role == "reviewer":
        instruction += ("\n本次为有界分批复核，覆盖本批所有 findings（至多16条）。"
            "输出紧凑JSON：{\"reviews\":[{\"i\":0,\"a\":\"INCONCLUSIVE\",\"c\":\"静态线索\",\"m\":\"无运行证据\"}]}。"
            "i 是本批 findings 的零基索引；a 必须逐项等于 comparisons 的固定判定。"
            "c为简短反证/复核说明，m为缺失证据；每项c和m合计不超过16个字符。"
            "不要输出全局ID或其他字段；不要遗漏、重复或增加索引。"
            "程序按索引绑定并回填完整finding_id、intent_id、artifact_refs，"
            "模型不能修改这些绑定；整批紧凑UTF-8回复不得超过2048字节。")
    return {"version": PROMPT_VERSION, "sha256": sha256(instruction.encode()).hexdigest(),
            "system": instruction}
