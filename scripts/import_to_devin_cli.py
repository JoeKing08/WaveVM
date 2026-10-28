#!/usr/bin/env python3
"""Convert a Devin cloud session export into a Devin CLI local session that
`devin -r <SESSION_ID>` can open.

The tool reads the ATIF-style JSON produced from a cloud session's event log
(or a messages dump from the Devin REST API), keeps only the user/assistant
conversation (optionally folding tool calls into text), and writes it in one
of the two on-disk formats Devin CLI uses for local sessions: the default
SQLite store (sessions.db) or the experimental folder store (meta.json +
log.jsonl). It never touches other sessions; an existing session id is an
error. Python 3.8+, no third-party dependencies.

Devin 云端会话 → Devin CLI 本地会话：给写项目的 AI 看的用法说明
================================================================
实测环境：Devin CLI v3000.11.205（Linux，~/.local/bin/devin）
  - 写入后 `devin list` 能列出会话，选中后进入 resume 流程
  - files 模式下，CLI 自己的解析器读取并回写了全部节点（字段已被官方代码校验）
  - 未验证：登录后 resume 继续对话（需要账号）
  - 只恢复聊天上下文；云端 VM 的 shell / 浏览器 / 文件 / 后台任务不会恢复

一、产物长什么样
----------------
--format sqlite（默认，CLI 当前默认存储）：
  往 ~/.local/share/devin/cli/sessions.db 里写入
    sessions        1 行（id、cwd、model、title、main_chain_id=最后一个节点）
    message_nodes   每条消息 1 行，node_id 从 1 起、parent_node_id 指向上一条
    prompt_history  每条用户消息 1 行
  chat_message 列的 JSON：
    {"role":"user"|"assistant","content":"...",
     "metadata":{"is_user_input":true,"created_at":"2026-10-16T10:00:28Z"}}
  注意 created_at 必须是 RFC 3339 字符串，不能是毫秒数（否则 CLI 当作损坏会话）。

--format files（实验性 folder store，需 DEVIN_SESSION_STORE=files）：
  <sessions-dir>/cli/sessions/<SESSION_ID>/
    meta.json     会话元数据（v、id、working_directory、model、title、main_chain_id…）
    log.jsonl     每行一个节点：
      {"kind":"node","at":<ms>,"node":{"id":1,"parent_id":null,"metadata":null,
        "message":{"message_id":"<uuid>","role":"user","content":"...","metadata":{...}}}}
  默认 sessions-dir 为 ~/.local/share/devin（即 DEVIN_SESSIONS_DIR 的默认值）。
  CLI 以 files 模式首次启动时会自动把旧 sessions.db 迁移进这个目录。

二、输入：云端会话怎么"翻"出来
------------------------------
A) 在云端会话里让 Devin 自己导（已实测）：
   Devin 有内置工具 devin_session_events（action=list 分页拿全部事件 id，
   action=details 每批 20 个拿正文），把 user_message / devin_message /
   devin_thoughts / 工具事件整理成下面的 ATIF 风格 JSON：
     {"schema_version":"ATIF-v1.7","session_id":"devin-<id>",
      "steps":[{"step_id":1,"timestamp":"2026-10-16 10:00:28","source":"user","message":"..."},
               {"step_id":2,"timestamp":"...","source":"agent","message":"..."},
               {"step_id":3,"timestamp":"...","source":"agent",
                "tool_calls":[{"function_name":"shell","arguments":{"command":"..."}}]}]}
   timestamp 为 UTC，格式 "%Y-%m-%d %H:%M:%S"。
B) 用 Devin REST API（文档有、本脚本未实测）：
   GET https://api.devin.ai/v3/enterprise/sessions/{devin_id}/messages
   返回 {"items":[{"created_at":<unix>,"source":"devin"|"user","message":"..."}],
         "end_cursor":...,"has_next_page":...}
   把所有页的 items 合并存成 JSON（{"items":[...]} 或纯数组）后用 --from-messages 读入。
   见 https://docs.devin.ai/api-reference

三、怎么跑
----------
1) 写进默认 SQLite 库（先退出所有 Devin CLI 进程，避免锁库）：
     python3 import_to_devin_cli.py devin_session_xxx.atif.json --include-tools
2) 生成 files 模式的会话文件夹：
     python3 import_to_devin_cli.py devin_session_xxx.atif.json --format files --include-tools
3) 先写到临时目录检查，再手动拷贝：
     python3 import_to_devin_cli.py devin_session_xxx.atif.json --format files --sessions-dir /tmp/out
4) 输入是 REST API 的 messages dump：
     python3 import_to_devin_cli.py messages.json --from-messages --id cloud-xxxx

成功时 stdout 打印写入的消息数、会话 id 和 resume 命令。

四、装到本机并 resume（不要动其它已有会话）
------------------------------------------
sqlite：脚本已直接写入 sessions.db，直接
     devin -r <SESSION_ID>
files：把 <sessions-dir>/cli/sessions/<SESSION_ID>/ 整个文件夹放到
     ~/.local/share/devin/cli/sessions/<SESSION_ID>/，然后
     DEVIN_SESSION_STORE=files devin -r <SESSION_ID>
   （或在 ~/.config/devin/config.json 里设 "session_store": "files"）
可选校验（不发消息、不调模型）：devin list 里能看到标题和 id 即可。
失败排查：~/.local/share/devin/cli/logs/*.log 里搜 "import" / "unreadable" / "parse"。

五、映射规则（实现侧摘要）
--------------------------
  - source=user 的 message            → role=user，metadata.is_user_input=true
  - source=agent 的 message           → role=assistant
  - devin_thoughts（内部思考）         → 丢弃
  - 工具调用                           → 默认丢弃；--include-tools 时折叠成
                                         "[tool <name>] <command 前 300 字>" 并前置到下一条助手消息
  - 连续同角色消息合并为一条（CLI 期望 user/assistant 交替）
  - 第一条不是 user 时补一条占位 user 消息
  - 会话 id 默认 "cloud-" + 云端 id 前 8 位，--id 可覆盖
  - backend_type=local_fusion，agent_mode=auto，model 由 --model 指定（默认 claude-sonnet-4）

六、重要限制（务必读）
----------------------
  1. 只恢复对话文本，云端 VM 的现场状态一律丢失；工具输出默认不带。
  2. 字段是从 CLI 二进制和数据库触发器反推并经 files 模式解析器校验的，
     CLI 升级后格式可能变化；出问题先看第四节的日志。
  3. 写 sqlite 前退出 CLI；脚本不会覆盖同 id 会话，重复导入请换 --id。
  4. 导出内容可能含密钥/密码，要 push 到 GitHub 前先用 redact_session.py 之类脱敏
     （log.jsonl 可直接喂它；sqlite 格式不行）。
  5. 不要把结果当成"可热续跑"的生产会话，更适合回顾上下文或继续纯对话。

七、最短操作清单
----------------
  [ ] 拿到 ATIF 风格 JSON（或 API messages dump）
  [ ] 退出 Devin CLI
  [ ] python3 import_to_devin_cli.py <export.json> [--format files] [--include-tools] [--id ...]
  [ ] 记下 stdout 里的 SESSION_ID
  [ ] devin list 看到会话 → devin -r <SESSION_ID>（files 模式加 DEVIN_SESSION_STORE=files）
"""

import argparse, json, os, sqlite3, time, datetime

def rfc3339(ms):
    return datetime.datetime.fromtimestamp(ms/1000, tz=datetime.timezone.utc).isoformat().replace("+00:00","Z")

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("export", help="ATIF-style JSON export (or REST API messages dump with --from-messages)")
ap.add_argument("--db", default=os.path.expanduser("~/.local/share/devin/cli/sessions.db"), help="sessions.db path (sqlite format)")
ap.add_argument("--id", help="local session id (default: cloud-<first 8 chars of cloud id>)")
ap.add_argument("--cwd", default=os.getcwd(), help="working_directory recorded in the session (default: current dir)")
ap.add_argument("--model", default="claude-sonnet-4", help="model id recorded in the session")
ap.add_argument("--from-messages", action="store_true", help="input is a Devin REST API messages dump ({\"items\":[...]} or a list) instead of ATIF JSON")
ap.add_argument("--include-tools", action="store_true", help="append tool-call summaries as assistant text")
ap.add_argument("--format", choices=["sqlite","files"], default="sqlite", help="sqlite: write into sessions.db (default store); files: write <sessions-dir>/cli/sessions/<id>/{meta.json,log.jsonl} for DEVIN_SESSION_STORE=files")
ap.add_argument("--sessions-dir", default=os.path.expanduser("~/.local/share/devin"), help="DEVIN_SESSIONS_DIR root (files format)")
a = ap.parse_args()

doc = json.load(open(a.export, encoding="utf-8"))
if a.from_messages:
    items = doc["items"] if isinstance(doc, dict) else doc
    steps = []
    for i, m in enumerate(items, 1):
        t = datetime.datetime.fromtimestamp(m["created_at"], tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        steps.append({"step_id": i, "timestamp": t, "source": "user" if m.get("source") == "user" else "agent", "message": m.get("message", "")})
    doc = {"session_id": (a.id or "api-import"), "steps": steps}
sid = a.id or ("cloud-" + doc.get("session_id", "import").replace("devin-", "")[:8])
title = doc.get("title") or f"Imported from {doc.get('session_id','cloud session')}"

def ts(s):
    try:
        return int(datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)

msgs = []
pending_tools = []
for st in doc["steps"]:
    t = ts(st.get("timestamp", ""))
    if st["source"] == "user" and st.get("message"):
        msgs.append(("user", st["message"], t))
    elif st["source"] == "agent" and st.get("message"):
        text = st["message"]
        if a.include_tools and pending_tools:
            text = "\n".join(pending_tools) + "\n\n" + text
        pending_tools = []
        msgs.append(("assistant", text, t))
    elif st["source"] == "agent" and st.get("tool_calls") and a.include_tools:
        for tc in st["tool_calls"]:
            pending_tools.append(f"[tool {tc['function_name']}] {tc['arguments'].get('command','')[:300]}")

if not msgs:
    raise SystemExit("no messages found in export")
if msgs[0][0] != "user":
    msgs.insert(0, ("user", f"(imported from Devin cloud session {doc.get('session_id')})", msgs[0][2]))
# merge consecutive same-role messages (CLI expects alternation)
merged = []
for role, text, t in msgs:
    if merged and merged[-1][0] == role:
        merged[-1] = (role, merged[-1][1] + "\n\n" + text, t)
    else:
        merged.append((role, text, t))

if a.format == "files":
    import uuid
    d = os.path.join(a.sessions_dir, "cli", "sessions", sid)
    if os.path.exists(d):
        raise SystemExit(f"{d} already exists; pass --id")
    os.makedirs(d)
    excerpts = []
    with open(os.path.join(d, "log.jsonl"), "w", encoding="utf-8") as f:
        for i, (role, text, t) in enumerate(merged, 1):
            meta = {"num_tokens": None, "is_user_input": True if role == "user" else None, "request_id": None,
                    "metrics": None, "finish_reason": None, "created_at": rfc3339(t)}
            node = {"id": i, "parent_id": None if i == 1 else i - 1, "metadata": None,
                    "message": {"message_id": str(uuid.uuid4()), "role": role, "content": text, "metadata": meta}}
            f.write(json.dumps({"kind": "node", "at": t, "node": node}, ensure_ascii=False) + "\n")
            excerpts.append(text)
    meta = {"v": 1, "id": sid, "working_directory": a.cwd, "backend_type": "local_fusion", "model": a.model,
            "agent_mode": "auto", "created_at": merged[0][2], "last_activity_at": merged[-1][2], "title": title,
            "hidden": False, "main_chain_id": len(merged), "workspace_dirs": [], "has_user_input": True,
            "metadata": {}, "excerpts": excerpts[:8]}
    json.dump(meta, open(os.path.join(d, "meta.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"wrote {len(merged)} messages to {d}\nresume with: DEVIN_SESSION_STORE=files devin -r {sid}")
    raise SystemExit(0)

c = sqlite3.connect(a.db)
if c.execute("select 1 from sessions where id=?", (sid,)).fetchone():
    raise SystemExit(f"session {sid} already exists; pass --id")
trig = dict(c.execute("select name, sql from sqlite_master where type='trigger'").fetchall())
old_sqlite = tuple(map(int, sqlite3.sqlite_version.split("."))) < (3, 43)
if old_sqlite:
    for n in trig: c.execute(f"drop trigger {n}")

node = 0
parent = None
for role, text, t in merged:
    node += 1
    cm = {"role": role, "content": text, "metadata": {"created_at": rfc3339(t)}}
    if role == "user":
        cm["metadata"]["is_user_input"] = True
    c.execute("insert into message_nodes(session_id,node_id,parent_node_id,chat_message,created_at) values(?,?,?,?,?)",
              (sid, node, parent, json.dumps(cm, ensure_ascii=False), t))
    parent = node
    if role == "user":
        c.execute("insert into prompt_history(content,timestamp,session_id,is_shell) values(?,?,?,0)", (text, t, sid))

c.execute("insert into sessions(id,working_directory,backend_type,model,agent_mode,created_at,last_activity_at,title,main_chain_id,hidden) values(?,?,?,?,?,?,?,?,?,0)",
          (sid, a.cwd, "local_fusion", a.model, "auto", merged[0][2], merged[-1][2], title, node))
if old_sqlite:
    for n, s in trig.items(): c.execute(s)
c.commit()
print(f"imported {len(merged)} messages into {a.db} as session {sid}\nresume with: devin -r {sid}")
