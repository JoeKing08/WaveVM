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
