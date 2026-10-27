#!/usr/bin/env python3
"""Convert a Grok Bot ReadTranscript JSONL into a Grok Build session that
`grok --resume <SESSION_ID>` can open.

The tool reads oldest-first Grok Bot transcript JSONL (or assembles it from
ReadTranscript page dumps via --from-pages), maps user/assistant/tool turns into
ACP session/update events, and writes summary.json + updates.jsonl under
<out>/<SESSION_ID>/. It never touches other sessions. Python 3.10+, no
third-party dependencies.

Grok Bot 会话 → Grok Build 会话：给写项目的 AI 看的用法说明
============================================================
配套脚本：同目录下的 bot_to_grok_build.py（Python 3.10+，无第三方依赖）
作者场景：把 Grok Bot（桌面助手）的对话转录，转成 Grok Build（CLI `grok`）
能 `grok --resume <SESSION_ID>` 打开的本地会话包。

已在 Ubuntu（cwd=/home/joeking）实测通过：
  - grok sessions list 能列出转换出的会话
  - grok export 能导出 Markdown
  - grok --resume <id> 能打开 TUI（窗口标题为会话标题）
  - 只恢复聊天上下文；工具现场状态（shell/浏览器/后台任务等）不会恢复


一、产物长什么样
----------------
转换成功后会生成：

  <out>/<SESSION_ID>/
    summary.json      # 会话元数据（id、cwd、标题、模型等）
    updates.jsonl     # ACP session/update 流（按时间从旧到新）

安装到本机时，目录必须落在：

  ~/.grok/sessions/<URL编码后的cwd>/<SESSION_ID>/

例：cwd=/home/joeking → 目录名为 %2Fhome%2Fjoeking
即：

  ~/.grok/sessions/%2Fhome%2Fjoeking/<SESSION_ID>/{summary.json,updates.jsonl}


二、输入：Grok Bot 转录 JSONL
-----------------------------
每行一个 JSON，**必须 oldest-first**（最旧在前）：

  {"role":"user"|"assistant"|"tool","message":{"content":[...]}}

来源：在 Grok Bot **主 Agent**（不是 executor 子代理）里调用 ReadTranscript：

  CallDynamicTool
    namespace: cursor
    toolName: ReadTranscript
    arguments: {}            # 不传 session_id → 读当前对话
    write_to_file: true

注意：
  - 返回默认是 **最新在前**；要用 before=<firstIndex> 翻页，直到出现
    “This is the start of the transcript.”
  - executor 子代理通常调不了 cursor/ReadTranscript，请在主对话拉 transcript。
  - 也可以把每一页 dump 存进一个目录，用脚本的 --from-pages 自动拼成 oldest-first。


二½、分页 dump 规则（--from-pages）
--------------------------------
拉全量 transcript 时请连续翻页，避免 dump 自身留下空洞：

  1. 用 ReadTranscript + before=<本页 firstIndex> 一直翻到出现
     “This is the start of the transcript.”（覆盖到最旧）。
  2. 翻页结束后，**再拉一次最新 tip**（不带 before，或等价拿到当前最新一页）。
  3. 不要在「最后一页 mid-page 的 end」和「tip 页的 start」之间留洞；
     若 tip 从 S 起而上一页只到 E 且 E+1 < S，assembler 会报 uncovered，
     并提示：dump incomplete: re-fetch ReadTranscript with before=<tip_start>。

关于 header 与缺位语义：

  - 页头 `positions A–B of N` 可能比正文 JSONL 行数多报（常见 ok = claimed−1..−17）。
    转换器把 A+ok..B 当作 **phantom tail**，不计入 missing/uncovered。
  - 重叠页（重复 dump）：优先采用 header `of N` 更大的页（更新快照），已填槽不覆盖。
  - dump 覆盖完整时，assemble 应报 uncovered 0
    （stderr：assembled N messages, positions contiguous 0..max）。
  - 若仍有 uncovered，那是 dump 真缺页（本脚本不会凭空发明消息），请补拉后再拼。



三、怎么跑转换脚本
----------------
1) 已有完整 oldest-first JSONL：

  python3 bot_to_grok_build.py \
    --transcript /path/to/grokbot-transcript.jsonl \
    --out /path/to/out_session_parent \
    --cwd /home/joeking \
    --title "可选标题"

2) 只有 ReadTranscript 分页 dump 目录：

  python3 bot_to_grok_build.py \
    --from-pages /path/to/pages_dir \
    --transcript /path/to/grokbot-transcript.jsonl \
    --out /path/to/out_session_parent \
    --cwd /home/joeking \
    --title "可选标题"

参数说明：
  --transcript    oldest-first JSONL 路径（可与 --from-pages 联用：先拼再转）
  --from-pages    ReadTranscript 分页文件所在目录
  --out           输出父目录；脚本会在其下创建 <session-id>/
  --cwd           写入 summary 的工作目录；也决定 sessions 子目录的 URL 编码名
                  默认建议与目标机器上要 resume 时的 cwd 一致（本机常用 /home/joeking）
  --title         generated_title / session_summary
  --session-id    指定 UUID；省略则自动生成新 uuid4

成功时 stdout 会打印 session_id、各类 update 计数、校验结果。


四、装到本机并 resume（不要改其它已有会话）
------------------------------------------
假设输出 id 为 <SESSION_ID>，目标机器 cwd 为 /home/joeking：

  mkdir -p ~/.grok/sessions/%2Fhome%2Fjoeking/<SESSION_ID>
  cp summary.json updates.jsonl ~/.grok/sessions/%2Fhome%2Fjoeking/<SESSION_ID>/

  cd /home/joeking
  grok --resume <SESSION_ID>

可选校验（不发消息、不调模型）：

  grok sessions list
  grok export <SESSION_ID> /tmp/check.md

若 grok_home 不在默认 ~/.grok，以 summary.json 里的 grok_home 为准。


五、映射规则（实现侧摘要，改脚本时参考）
--------------------------------------
  - 用户文本 → user_message_chunk
    （去掉行首 [tNu]、[Sent from machine …]；优先取 <user_query> 正文）
  - 助手对用户可见文本：优先 SendToUser 的 content → agent_message_chunk
  - 其它 tool_use → tool_call；对应 tool_result → tool_call_update（结果约截断 50KB）
  - 每个 turn 结束 → turn_completed（method=_x.ai/session/update，stop_reason=end_turn）
  - summary 里：current_model_id=grok-4.7，agent_name=grok-build-plan，sandbox_profile=off


六、重要限制（务必读）
--------------------
  1. 聊天上下文有机会恢复；**现场工具状态不会恢复**。
  2. 只拷贝目标会话目录下的 summary.json + updates.jsonl；不要动用户其它 session。
  3. resume 可能在该会话目录下生成派生文件（如 chat_history.jsonl），属正常现象。
  4. 不要把转换结果当成「可热续跑」的生产会话；更适合回顾上下文或继续纯对话。
  5. 用户偏好：未明确说 push 时不要 git push；批量改完再在对方要求时一次性 commit/push。


七、本机已验证过的示例会话（可选参考）
------------------------------------
  SESSION_ID: e4eb634d-96fa-42ea-9eb4-bfa5ff1a69de
  标题: 小浪 · Grok Bot 本会话
  位置（Ubuntu）:
    ~/.grok/sessions/%2Fhome%2Fjoeking/e4eb634d-96fa-42ea-9eb4-bfa5ff1a69de/

  验证命令：
    grok sessions list | grep e4eb634d
    grok export e4eb634d-96fa-42ea-9eb4-bfa5ff1a69de /tmp/export.md
    grok --resume e4eb634d-96fa-42ea-9eb4-bfa5ff1a69de   # 打开即可，可不发消息


八、给写项目 AI 的最短操作清单
----------------------------
  [ ] 拿到 oldest-first 的 grokbot-transcript.jsonl（或 pages 目录）
  [ ] python3 bot_to_grok_build.py --transcript ... --out ... --cwd /home/joeking --title "..."
  [ ] 记下 stdout 里的 session_id
  [ ] 只把 summary.json + updates.jsonl 拷进
        ~/.grok/sessions/%2Fhome%2Fjoeking/<session_id>/
  [ ] cd 到 --cwd 对应目录后执行：grok --resume <session_id>
  [ ] 用 sessions list / export 做本地校验；resume 测试时不要随便发会扣费的 prompt

完。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

TZ_SHANGHAI = timezone(timedelta(hours=8))
RESULT_TRUNCATE = 50_000
MODEL_ID = "grok-4.7"
AGENT_NAME = "grok-build-plan"
CHAT_FORMAT_VERSION = 1

# tool name -> (kind, label, read_only)
TOOL_META: dict[str, tuple[str, str, bool]] = {
    "Shell": ("execute", "Run Command", False),
    "AwaitShell": ("execute", "Await Command", False),
    "Read": ("read", "Read File", True),
    "WebSearch": ("search", "Web Search", True),
    "WebFetch": ("fetch", "Web Fetch", True),
    "GetDynamicTools": ("read", "List Dynamic Tools", True),
    "CallDynamicTool": ("execute", "Call Dynamic Tool", False),
    "ListMachines": ("read", "List Machines", True),
    "ListEmailInboxes": ("read", "List Email Inboxes", True),
    "SearchEmailThreads": ("search", "Search Email", True),
    "ReadEmailThread": ("read", "Read Email Thread", True),
    "ReadEmailAttachment": ("read", "Read Email Attachment", True),
    "CheckEmailInboxAvailability": ("read", "Check Inbox Availability", True),
    "ClaimEmailInbox": ("edit", "Claim Email Inbox", False),
    "CopyToBox": ("edit", "Copy To Box", False),
    "CopyFromBox": ("edit", "Copy From Box", False),
    "UploadFile": ("edit", "Upload File", False),
    "DownloadFile": ("fetch", "Download File", False),
    "SendToUser": ("other", "Send To User", False),
    "UpdateMemory": ("edit", "Update Memory", False),
    "Task": ("execute", "Task", False),
    "Skill": ("execute", "Skill", False),
}

STRIP_LINE_PREFIXES = (
    re.compile(r"^\[tNu\]\s*"),
    re.compile(r"^\[Sent from machine [^\]]+\]\s*"),
)

USER_TS_RE = re.compile(
    r"<timestamp>\s*([^<]+?)\s*</timestamp>",
    re.IGNORECASE,
)
USER_QUERY_RE = re.compile(
    r"<user_query>\s*([\s\S]*?)\s*</user_query>",
    re.IGNORECASE,
)
# e.g. Tuesday, Oct 13, 2026, 8:38 PM (UTC+8)
TS_PARSE_RE = re.compile(
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2}),\s+(?P<year>\d{4}),\s+"
    r"(?P<hour>\d{1,2}):(?P<minute>\d{2})\s*(?P<ampm>AM|PM)"
    r"(?:\s*\([^)]+\))?",
    re.IGNORECASE,
)
MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

PAGE_HEADER_RE = re.compile(
    r"Transcript of this (?:conversation|session), positions (\d+)[–-](\d+) of (\d+):?",
)


def parse_user_timestamp(text: str, fallback: float) -> float:
    m = USER_TS_RE.search(text)
    if not m:
        return fallback
    raw = m.group(1).strip()
    m2 = TS_PARSE_RE.search(raw)
    if not m2:
        return fallback
    month = MONTHS[m2.group("month").lower()[:3]]
    day = int(m2.group("day"))
    year = int(m2.group("year"))
    hour = int(m2.group("hour"))
    minute = int(m2.group("minute"))
    ampm = m2.group("ampm").upper()
    if ampm == "PM" and hour != 12:
        hour += 12
    if ampm == "AM" and hour == 12:
        hour = 0
    dt = datetime(year, month, day, hour, minute, tzinfo=TZ_SHANGHAI)
    return dt.timestamp()


def strip_user_text(text: str) -> str:
    m = USER_QUERY_RE.search(text)
    body = m.group(1) if m else text
    # Also strip outer timestamp wrapper leftovers
    body = USER_TS_RE.sub("", body).strip()
    lines = body.splitlines()
    cleaned: list[str] = []
    for line in lines:
        skip = False
        for rx in STRIP_LINE_PREFIXES:
            if rx.match(line):
                skip = True
                break
        if skip:
            continue
        # strip prefix in-place if embedded at start after spaces
        for rx in STRIP_LINE_PREFIXES:
            line = rx.sub("", line)
        cleaned.append(line)
    # drop leading empty lines
    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    return "\n".join(cleaned).strip()


def tool_meta(name: str) -> tuple[str, str, bool]:
    if name in TOOL_META:
        return TOOL_META[name]
    # heuristics
    low = name.lower()
    if any(k in low for k in ("read", "list", "get", "search", "check", "fetch")):
        return ("read", name, True)
    if any(k in low for k in ("shell", "await", "exec", "run", "call")):
        return ("execute", name, False)
    if any(k in low for k in ("write", "edit", "upload", "copy", "claim", "delete", "update")):
        return ("edit", name, False)
    return ("other", name, False)


def iso_z(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def truncate(s: str, n: int = RESULT_TRUNCATE) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n…[truncated {len(s) - n} chars]"


def result_to_text(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, indent=2)
    except TypeError:
        return str(result)


class SessionBuilder:
    def __init__(self, session_id: str, cwd: str, title: str | None):
        self.session_id = session_id
        self.cwd = cwd
        self.title = title
        self.events: list[dict[str, Any]] = []
        self.event_n = 0
        self.num_messages = 0
        self.num_chat_messages = 0
        self.created_at: float | None = None
        self.updated_at: float | None = None
        self._clock: float | None = None
        self._pending_tools: dict[str, dict[str, Any]] = {}

    def _next_event_id(self) -> str:
        self.event_n += 1
        return f"{self.session_id}-{self.event_n}"

    def _bump(self, ts: float) -> tuple[int, int]:
        if self._clock is None or ts > self._clock:
            self._clock = ts
        else:
            self._clock += 0.001
        if self.created_at is None:
            self.created_at = self._clock
        self.updated_at = self._clock
        sec = int(self._clock)
        ms = int(self._clock * 1000)
        return sec, ms

    def emit(
        self,
        session_update: str,
        update_body: dict[str, Any],
        ts: float,
        *,
        xai_method: bool = False,
        extra_meta: dict[str, Any] | None = None,
    ) -> None:
        sec, ms = self._bump(ts)
        meta = {
            "eventId": self._next_event_id(),
            "agentTimestampMs": ms,
        }
        if extra_meta:
            meta.update(extra_meta)
        update = {"sessionUpdate": session_update, **update_body}
        method = "_x.ai/session/update" if xai_method else "session/update"
        self.events.append(
            {
                "timestamp": sec,
                "method": method,
                "params": {
                    "sessionId": self.session_id,
                    "update": update,
                    "_meta": meta,
                },
            }
        )
        self.num_messages += 1

    def add_user(self, text: str, ts: float) -> None:
        cleaned = strip_user_text(text)
        if not cleaned:
            return
        self.emit(
            "user_message_chunk",
            {
                "content": {"type": "text", "text": cleaned},
                "_meta": {"modelId": MODEL_ID, "promptIndex": self.num_chat_messages},
            },
            ts,
        )
        self.num_chat_messages += 1

    def add_agent_message(self, text: str, ts: float) -> None:
        if not text:
            return
        self.emit(
            "agent_message_chunk",
            {"content": {"type": "text", "text": text}},
            ts,
        )
        self.num_chat_messages += 1

    def add_thought(self, text: str, ts: float) -> None:
        if not text:
            return
        self.emit(
            "agent_thought_chunk",
            {"content": {"type": "text", "text": text}},
            ts,
        )

    def add_tool_call(self, tool_use_id: str, name: str, raw_input: Any, ts: float) -> None:
        kind, label, read_only = tool_meta(name)
        if not isinstance(raw_input, dict):
            raw_input = {"value": raw_input}
        self._pending_tools[tool_use_id] = {
            "name": name,
            "kind": kind,
            "label": label,
            "read_only": read_only,
            "rawInput": raw_input,
        }
        self.emit(
            "tool_call",
            {
                "toolCallId": tool_use_id,
                "title": name,
                "rawInput": raw_input,
                "_meta": {
                    "x.ai/tool": {
                        "version": 1,
                        "name": name,
                        "kind": kind,
                        "namespace": "grok_build",
                        "label": label,
                        "read_only": read_only,
                    }
                },
            },
            ts,
        )

    def add_tool_result(self, tool_use_id: str, name: str | None, result: Any, ts: float) -> None:
        pending = self._pending_tools.get(tool_use_id, {})
        name = name or pending.get("name") or "tool"
        kind = pending.get("kind") or tool_meta(name)[0]
        label = pending.get("label") or name
        raw_input = pending.get("rawInput") or {}
        text = truncate(result_to_text(result))
        title = name
        if name == "Shell" and isinstance(raw_input, dict) and raw_input.get("command"):
            cmd = str(raw_input["command"])
            title = f"Execute `{cmd[:120]}{'…' if len(cmd) > 120 else ''}`"
        self.emit(
            "tool_call_update",
            {
                "toolCallId": tool_use_id,
                "kind": kind,
                "title": title,
                "status": "completed",
                "content": [
                    {
                        "type": "content",
                        "content": {"type": "text", "text": text},
                    }
                ],
                "rawInput": raw_input,
                "_meta": {
                    "x.ai/tool": {
                        "version": 1,
                        "name": name,
                        "kind": kind,
                        "namespace": "grok_build",
                        "label": label,
                        "read_only": pending.get("read_only", False),
                    }
                },
            },
            ts,
        )

    def add_turn_completed(self, ts: float, prompt_id: str | None = None) -> None:
        self.emit(
            "turn_completed",
            {
                "prompt_id": prompt_id or str(uuid.uuid4()),
                "stop_reason": "end_turn",
            },
            ts,
            xai_method=True,
        )

    def summary(self) -> dict[str, Any]:
        created = self.created_at or datetime.now(timezone.utc).timestamp()
        updated = self.updated_at or created
        title = self.title or "Imported Grok Bot chat"
        grok_home = str(Path(self.cwd) / ".grok")
        return {
            "info": {"id": self.session_id, "cwd": self.cwd},
            "session_summary": title,
            "generated_title": title,
            "created_at": iso_z(created),
            "updated_at": iso_z(updated),
            "last_active_at": iso_z(updated),
            "num_messages": self.num_messages,
            "num_chat_messages": self.num_chat_messages,
            "current_model_id": MODEL_ID,
            "chat_format_version": CHAT_FORMAT_VERSION,
            "grok_home": grok_home,
            "agent_name": AGENT_NAME,
            "sandbox_profile": "off",
        }


def load_transcript_jsonl(path: Path) -> list[dict[str, Any]]:
    msgs: list[dict[str, Any]] = []
    with path.open() as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"Bad JSONL at {path}:{lineno}: {e}") from e
            if "role" in obj and "message" in obj:
                msgs.append(obj)
            elif "role" in obj and "content" in obj:
                # alternate shape
                msgs.append({"role": obj["role"], "message": {"content": obj["content"]}})
            else:
                # skip headers / paging notes
                continue
    return msgs


def _cluster_pos_ranges(positions: list[int]) -> list[tuple[int, int]]:
    """Collapse sorted positions into inclusive (start, end) runs."""
    if not positions:
        return []
    ranges: list[tuple[int, int]] = []
    a = b = positions[0]
    for p in positions[1:]:
        if p == b + 1:
            b = p
        else:
            ranges.append((a, b))
            a = b = p
    ranges.append((a, b))
    return ranges


def _format_pos_clusters(ranges: list[tuple[int, int]], limit: int = 8) -> str:
    parts: list[str] = []
    for a, b in ranges[:limit]:
        parts.append(str(a) if a == b else f"{a}–{b}")
    extra = len(ranges) - limit
    s = ", ".join(parts)
    if extra > 0:
        s += f", …(+{extra} more clusters)"
    return s


# Outer-page footer only: match at line start. Nested tool_result text may contain
# the string "Older messages remain:" / "This is the start…"; JSONL normally keeps
# those escaped inside a single line, so a line-start anchor is enough.
PAGE_FOOTER_RE = re.compile(
    r"^(?:Older messages remain:|This is the start of the transcript\.)",
    re.MULTILINE,
)


def assemble_from_pages(pages_dir: Path) -> list[dict[str, Any]]:
    """Merge ReadTranscript page dump files into oldest-first messages.

    Overlap rule: parse pages with higher header ``of N`` total first (fresher
    snapshot), then first fill wins — never overwrite an already-filled slot.

    Header ``positions A–B`` may over-claim vs actual JSONL lines in the body
    (ok often = claimed−1..−17). Trailing claimed-but-absent positions are
    *phantom tails* and are not reported as missing. True holes (no page covers
    them) are *uncovered* dump gaps and get the warning.
    """
    # (total, start, end, body_after_header, path) — sort key applied below
    page_metas: list[tuple[int, int, int, str, Path]] = []
    for path in sorted(pages_dir.iterdir()):
        if not path.is_file():
            continue
        text = path.read_text(errors="replace")
        # strip untrusted wrappers if present
        text = re.sub(
            r"</?cursor_untrusted_data[^>]*>",
            "",
            text,
        )
        text = re.sub(
            r"</?cursor_untrusted_data_redacted[^>]*>",
            "",
            text,
        )
        m = PAGE_HEADER_RE.search(text)
        if not m:
            continue
        start, end, total = int(m.group(1)), int(m.group(2)), int(m.group(3))
        body = text[m.end() :]
        # Line-start footer of the outer page (see PAGE_FOOTER_RE).
        body = PAGE_FOOTER_RE.split(body, maxsplit=1)[0]
        page_metas.append((total, start, end, body, path))

    # Fresher snapshot first (higher total), then wider claimed span, then name.
    page_metas.sort(key=lambda t: (-t[0], -(t[2] - t[1]), str(t[4])))

    slots: dict[int, dict[str, Any]] = {}
    phantom_tails: set[int] = set()
    total_hint = 0
    tip_start: int | None = None
    tip_end: int | None = None

    for total, start, end, body, _path in page_metas:
        total_hint = max(total_hint, total)
        if tip_end is None or end > tip_end:
            tip_end = end
            tip_start = start

        pos = start
        ok = 0
        for line in body.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "role" in obj:
                # First fill wins (fresher pages already processed above).
                if pos not in slots:
                    slots[pos] = obj
                pos += 1
                ok += 1

        # Phantom tail: header claimed [start, end] but body only yielded `ok` lines.
        claimed = end - start + 1
        if ok < claimed:
            for p in range(start + ok, end + 1):
                phantom_tails.add(p)

    if not slots:
        raise SystemExit(f"No transcript pages found in {pages_dir}")

    # A later/overlapping page may have filled a position another page phantoms.
    phantom_tails -= slots.keys()

    filled = len(slots)
    max_pos = max(slots)
    uncovered = [
        i for i in range(0, max_pos + 1)
        if i not in slots and i not in phantom_tails
    ]

    if uncovered:
        clusters = _cluster_pos_ranges(uncovered)
        print(
            f"warning: uncovered {len(uncovered)} positions "
            f"({_format_pos_clusters(clusters)}); "
            f"filled {filled}, max_pos {max_pos} (total hint {total_hint})",
            file=sys.stderr,
        )
        # Gap immediately before tip page → dump skipped a mid→tip range.
        if tip_start is not None and (tip_start - 1) in uncovered:
            print(
                f"dump incomplete: re-fetch ReadTranscript with before={tip_start}",
                file=sys.stderr,
            )
    else:
        print(
            f"assembled {filled} messages, positions contiguous 0..{max_pos}",
            file=sys.stderr,
        )

    return [slots[i] for i in sorted(slots)]


def convert_messages(msgs: list[dict[str, Any]], builder: SessionBuilder) -> None:
    # Start low so parsed user <timestamp> values win over "now".
    clock = 0.0
    turn_open = False
    prompt_id: str | None = None

    def close_turn(ts: float) -> None:
        nonlocal turn_open, prompt_id
        if turn_open:
            builder.add_turn_completed(ts, prompt_id)
            turn_open = False
            prompt_id = None

    for msg in msgs:
        role = msg.get("role")
        content = msg.get("message", {}).get("content") or []
        if not isinstance(content, list):
            content = [content]

        if role == "user":
            close_turn(clock)
            text_parts = [
                p.get("text", "")
                for p in content
                if isinstance(p, dict) and p.get("type") == "text"
            ]
            text = "\n".join(text_parts)
            ts = parse_user_timestamp(text, clock + 1)
            clock = max(clock + 1, ts)
            builder.add_user(text, clock)
            turn_open = True
            prompt_id = str(uuid.uuid4())
            continue

        if role == "assistant":
            clock += 0.5
            # Prefer SendToUser content as agent_message_chunk
            send_texts: list[str] = []
            thoughts: list[str] = []
            tool_uses: list[dict[str, Any]] = []
            for part in content:
                if not isinstance(part, dict):
                    continue
                ptype = part.get("type")
                if ptype == "tool_use":
                    name = part.get("name") or ""
                    if name == "SendToUser":
                        inp = part.get("input") or {}
                        if isinstance(inp, dict) and inp.get("content"):
                            send_texts.append(str(inp["content"]))
                        # still record as tool for fidelity? skip — content is the message
                    else:
                        tool_uses.append(part)
                elif ptype == "text":
                    t = (part.get("text") or "").strip()
                    if t:
                        thoughts.append(t)
                elif ptype == "thinking":
                    t = (part.get("thinking") or part.get("text") or "").strip()
                    if t:
                        thoughts.append(t)

            for t in thoughts:
                # If we also have SendToUser, treat plain text as thought
                if send_texts:
                    builder.add_thought(t, clock)
                else:
                    # no SendToUser — surface as agent message
                    builder.add_agent_message(t, clock)
                clock += 0.01

            for t in send_texts:
                builder.add_agent_message(t, clock)
                clock += 0.01

            for tu in tool_uses:
                tid = tu.get("id") or f"call-{uuid.uuid4()}"
                # tool ids sometimes contain newline-joined dual ids
                if isinstance(tid, str) and "\n" in tid:
                    tid = tid.split("\n", 1)[0]
                builder.add_tool_call(tid, tu.get("name") or "tool", tu.get("input") or {}, clock)
                clock += 0.01

            turn_open = True
            continue

        if role == "tool":
            clock += 0.2
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") != "tool_result" and "tool_use_id" not in part:
                    # some shapes nest tool_result fields at top level
                    if "result" not in part and "content" not in part:
                        continue
                tid = part.get("tool_use_id") or part.get("toolUseId") or ""
                if isinstance(tid, str) and "\n" in tid:
                    tid = tid.split("\n", 1)[0]
                name = part.get("name")
                if name == "SendToUser":
                    # message already emitted from tool_use input
                    continue
                result = part.get("result")
                if result is None:
                    result = part.get("content")
                builder.add_tool_result(tid, name, result, clock)
                clock += 0.01
            turn_open = True
            continue

    close_turn(clock + 0.5)


def validate_session(session_dir: Path, session_id: str) -> dict[str, int]:
    summary = json.loads((session_dir / "summary.json").read_text())
    sid = summary.get("info", {}).get("id")
    if sid != session_id:
        raise SystemExit(f"summary info.id {sid!r} != session id {session_id!r}")
    counts: dict[str, int] = {}
    bad = 0
    with (session_dir / "updates.jsonl").open() as f:
        for i, line in enumerate(f, 1):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"updates.jsonl line {i} not JSON: {e}") from e
            psid = obj.get("params", {}).get("sessionId")
            if psid != session_id:
                bad += 1
                print(f"warning: line {i} sessionId mismatch: {psid}", file=sys.stderr)
            su = obj.get("params", {}).get("update", {}).get("sessionUpdate", "?")
            counts[su] = counts.get(su, 0) + 1
    if bad:
        raise SystemExit(f"{bad} updates lines had wrong sessionId")
    return counts


def default_title_from_msgs(msgs: list[dict[str, Any]]) -> str:
    for msg in msgs:
        if msg.get("role") != "user":
            continue
        for p in msg.get("message", {}).get("content", []):
            if isinstance(p, dict) and p.get("type") == "text":
                cleaned = strip_user_text(p.get("text") or "")
                # skip hidden prompts
                if cleaned.startswith("[GROK_BOT_HIDDEN_PROMPT]"):
                    continue
                if not cleaned.strip():
                    continue
                one = cleaned.strip().splitlines()[0].strip()
                return (one[:80] + "…") if len(one) > 80 else one
    return "Imported Grok Bot chat"


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--transcript",
        type=Path,
        help="Oldest-first JSONL path (may be written when used with --from-pages)",
    )
    ap.add_argument(
        "--from-pages",
        type=Path,
        help="Directory of ReadTranscript page dumps; assemble oldest-first first",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("/workspace/grok-build-export/session"),
        help="Output parent directory; writes <out>/<session-id>/",
    )
    ap.add_argument(
        "--cwd",
        default="/home/joeking",
        help="Working directory recorded in summary (also URL-encodes sessions subdir)",
    )
    ap.add_argument(
        "--title",
        default=None,
        help="generated_title / session_summary (default: derived from first user text)",
    )
    ap.add_argument(
        "--session-id",
        default=None,
        help="Session UUID; omit to auto-generate uuid4",
    )
    args = ap.parse_args()

    if args.from_pages:
        msgs = assemble_from_pages(args.from_pages)
        if args.transcript:
            args.transcript.parent.mkdir(parents=True, exist_ok=True)
            with args.transcript.open("w") as f:
                for m in msgs:
                    f.write(json.dumps(m, ensure_ascii=False) + "\n")
            print(f"assembled {len(msgs)} messages → {args.transcript}")
    elif args.transcript:
        msgs = load_transcript_jsonl(args.transcript)
    else:
        ap.error("provide --transcript and/or --from-pages")

    session_id = args.session_id or str(uuid.uuid4())
    title = args.title or default_title_from_msgs(msgs)
    builder = SessionBuilder(session_id, args.cwd, title)
    convert_messages(msgs, builder)

    session_dir = args.out / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    summary = builder.summary()
    (session_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    )
    with (session_dir / "updates.jsonl").open("w") as f:
        for ev in builder.events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    counts = validate_session(session_dir, session_id)
    print(f"session_id={session_id}")
    print(f"out={session_dir}")
    print(f"transcript_messages={len(msgs)}")
    print(f"updates_lines={len(builder.events)}")
    print(f"num_messages={summary['num_messages']} num_chat_messages={summary['num_chat_messages']}")
    print(f"title={title!r}")
    print("counts:", json.dumps(counts, ensure_ascii=False))
    print(f"resume: grok --resume {session_id}")
    enc = "%2Fhome%2Fjoeking"
    print(f"copy to: ~/.grok/sessions/{enc}/{session_id}/")


if __name__ == "__main__":
    main()
