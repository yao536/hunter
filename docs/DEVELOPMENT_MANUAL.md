# Hunter — AI 自主漏洞挖掘平台开发手册

> **版本**: v1.2 · **代号**: Hunter · **更新日期**: 2026-08-15
>
> Hunter 是一套面向个人/小团队的 AI 自主漏洞挖掘平台，单机 Ubuntu + Docker 一键部署。工具仅限已获明确书面授权的目标使用，禁止商业用途。
>
> **v1.2 更新（本次）**：
> - **环境变量统一**：全部环境变量统一为 `HUNTER_*` 前缀，并兼容旧前缀（如 `DB_PATH`、`WORKER_WORK_ROOT`），升级无感
> - **数据自动采用**：启动时若 `hunter.db` 不存在而数据目录中恰好只有一个其它 `*.db` 文件，自动采用为初始数据库（R-005，§21）
> - **前端界面重设计**：控制台视觉与交互全面升级（§13）
> - **个人使用体验优化**：部署脚本简化，安装 / 升级更顺畅（§16/§17）
> - **MVP 范围**：核心闭环 = 任务管理 + 多引擎目标采集 + Worker ReAct 扫描 + Finding 复审 + 报告导出 + 看板（§20）
> - 手册 §1-§19 保留为 Hunter 的完整能力蓝图与远期扩展参考，MVP 实现范围以 §20 为准
>
> **v1.1 更新（历史）**：
> - §0 需求基线扩充为 460+ 行（从对话需求中提炼 60+ 条 Must/Should/Could 需求）
> - §10 通杀 Hunter 扩充为 13 个小节（覆盖 FingerprintExtractor / CandidateSearcher / PlanGenerator / ScopeGuard / VerifierPool / ResultAggregator 全链路）
> - §14 安全护栏升级为 **v3 无害化 PoC 白名单模型**（RCE / SSRF / XSS / SQL / 文件全部白名单化 + ToolInterceptor 集中管控 + SELF/TARGET 资源所有权 + 紧急熔断）
>
> **v1.0 更新（正式版）**：
> - Docker 一键部署（§16/§17）
> - 看板统计与报告导出（§11/§13）
> - 旧数据导入与兼容（§21）
>
> **v0.x 更新（原型阶段）**：
> - 核心闭环验证：任务编排 / 引擎采集 / LLM 分析 / Finding 审核

---

## 目录

- [0. 需求基线](#0-需求基线)
- [1. 系统架构总览](#1-系统架构总览)
- [2. 技术栈选型](#2-技术栈选型)
- [3. 目录结构](#3-目录结构)
- [4. 数据模型与持久层](#4-数据模型与持久层)
- [5. 多 Agent 协同设计](#5-多-agent-协同设计)
- [6. 工具链与执行沙箱](#6-工具链与执行沙箱)
- [7. 目标采集与多引擎适配](#7-目标采集与多引擎适配)
- [8. 漏洞检测引擎](#8-漏洞检测引擎)
- [9. LLM 集成与多供应商池](#9-llm-集成与多供应商池)
- [10. 通杀 Hunter 与情报沉淀](#10-通杀-hunter-与情报沉淀)
- [11. 报告生成与交付](#11-报告生成与交付)
- [12. RBAC 与审计日志](#12-rbac-与审计日志)
- [13. Web 控制台 (Vue 3)](#13-web-控制台-vue-3)
- [14. 安全护栏与熔断](#14-安全护栏与熔断)
- [15. 性能与并发调优](#15-性能与并发调优)
- [16. Docker 镜像与编排](#16-docker-镜像与编排)
- [17. 一键安装与升级](#17-一键安装与升级)
- [18. OpenAPI 与 SDK](#18-openapi-与-sdk)
- [19. 监控、运维与备份](#19-监控运维与备份)
- [20. 开发路线图 (MVP → GA)](#20-开发路线图-mvp--ga)
- [21. 数据导入与兼容（旧部署数据直接可用）](#21-数据导入与兼容旧部署数据直接可用)
- [附录 A: 关键 Prompt 模板](#附录-a-关键-prompt-模板)
- [附录 B: nuclei 模板适配指南](#附录-b-nuclei-模板适配指南)

---

## 0. 需求基线

> **本章是后续所有设计决策的唯一来源**。任何与本章冲突的实现都以本章为准。
>
> 本章汇总了从需求访谈中收集到的所有需求点，并按"业务定位 → 核心能力 → 安全约束 → 技术栈 → 部署形态"五个维度组织。每条需求都明确给出**优先级（Must/Should/Could）、验收标准、与其他需求的依赖关系**。

### 0.1 业务定位

#### R-001 【Must】全自动化漏洞挖掘

- **描述**：给定一个授权目标（IP / 域名 / URL），系统能**全自动**完成"目标采集 → 资产发现 → 漏洞扫描 → 漏洞验证 → 报告生成 → 结果复审"全流程，无需人工介入。
- **验收**：用户输入目标字符串 → 选择模板 → 点启动 → 数分钟后看板出现 Finding 列表（含证据与漏洞等级）。
- **依赖**：R-002（多 Agent 协作）、R-101（Worker ReAct）、R-201（v3 安全护栏）。

#### R-002 【Must】自有代码基线（迭代演进）

- **描述**：项目经过 v0.x 原型验证迭代而来，核心架构（ReAct Agent 范式、引擎采集、持久层）在多次迭代中**沉淀为稳定基线**，后续只做**增量演进**，不再从零重构。
- **保留**：ReAct Agent 范式（`app/agents/`）、工具白名单调用模式、任务编排（`app/orchestrator.py`）、SQLite + aiosqlite 持久层（`app/db/`）、Vue 3 前端（`frontend/`）、应用层 WAF（`app/waf.py`）、Token 鉴权（`app/security.py`）。
- **增强（MVP 内）**：环境变量前缀统一（`HUNTER_*`，兼容旧前缀）、旧数据自动采用（R-005）、部署脚本简化。
- **增强（远期）**：多供应商 LLM 池、RBAC 多角色、通杀 Hunter 增强、v3 无害化 PoC 护栏（见 §9/§10/§12/§14，非 MVP）。

#### R-003 【Must】单机部署（Ubuntu + Docker）

- **描述**：单机一台机器就能跑起来，无需分布式。**目标用户是个人/小团队**。
- **部署形态**：
  - Ubuntu 22.04 LTS 主机（4C8G 起步）
  - Docker 24+ + Docker Compose v2
  - 数据通过 volume 持久化：`hunter_data`（SQLite + 证据）、`hunter_work`（worker 工作区）——volume 命名/路径为自有持久层基线（R-005）
- **不在范围内**：多机分布式、K8s 集群部署（仅作为可选扩展，不在 MVP）。

#### R-004 【Should】后续可扩展为企业级

- **描述**：MVP 阶段按单机设计，但数据模型、API、模块边界都为未来扩展到企业版（多租户、分布式 Worker）预留空间。
- **措施**：所有外部接口（LLM / 引擎 / 工具）走接口抽象，方便替换实现。

#### R-005 【Must】旧部署数据导入 —— 复制旧数据卷即可用

- **描述**：用户可能已有长期运行的旧部署（SQLite 数据，含任务/目标/Finding/复审/通杀/情报记录）。Hunter 必须能**直接使用**这些数据，**无需任何迁移或转换**。
- **核心机制**：
  - Hunter 数据库采用 **UUID 主键（`String(32)`）+ 固定 8 张核心表**：相同表名、相同字段、相同主键、相同约束（§4.2）。
  - 默认库文件 `hunter.db`，默认路径 `/app/data/hunter.db`（Docker 内，volume `hunter_data:/app/data`）。
  - `app/db/session.py` 启动时若 `hunter.db` 不存在、而数据目录里恰好只有一个其它 `*.db` 文件，会自动复制它（连同 `-wal`/`-shm`）作为初始数据库（即"自动采用"）。
  - 因此用户只需把旧部署的数据卷（或卷内 `hunter.db`）复制到 Hunter 的数据卷，启动后历史任务 / 目标 / Finding / 复审结论 / 通杀 / 情报全部可见可用。
- **操作示例**（Ubuntu 宿主机）：
  ```bash
  # 推荐：一键导入脚本（自动探测源/目标卷、带覆盖保护，见 §21.3 方式 A）
  # 步骤：先停旧容器 → 把旧数据卷内容拷入 Hunter 数据卷 → docker compose up -d
  docker compose down                                    # 1. 停 Hunter 容器
  bash scripts/import-data.sh --from 旧部署数据卷 --to hunter_data   # 2. 导入旧数据
  docker compose up -d                                   # 3. 启动，数据自动采用

  # 备选：手动复制 db 文件
  sudo cp /var/lib/docker/volumes/旧部署数据卷/_data/hunter.db \
          /var/lib/docker/volumes/hunter_data/_data/hunter.db

  # 备选：绑定挂载（bind mount）直接指向旧数据目录
  #   docker-compose.yml 中 volumes: - /path/to/旧数据目录:/app/data
  ```
- **验收**：复制数据 → 启动 → 控制台任务列表、看板统计、Finding 复审页出现历史数据；新增任务照常工作。
- **依赖**：R-003（volume 持久化）、持久层自动迁移（§4.3）。
- **不在范围内（MVP）**：**不迁移、不转换、不重构**，保持简单直接，以换取"复制即用"。

---

### 0.2 核心能力

#### R-101 【Must】Worker ReAct Agent

- **描述**：每个目标分配一个 Worker Agent，运行 ReAct 循环（思考 → 工具调用 → 观察 → 再思考）。
- **参数**：
  - `max_rounds = 80`（单目标最多 80 轮 ReAct）
  - `timeout = 300s`（单 Worker 总超时）
- **能力**：自动选择工具、自动构造 payload、自动评估响应、自主判断"是否已经够形成 Finding"。
- **依赖**：R-201（v3 安全护栏，所有工具调用必须经过拦截器）。

#### R-102 【Must】多引擎目标采集

- **描述**：支持 6 大网络空间搜索引擎：**FOFA / Quake / Hunter / ZoomEye / Shodan / Censys**。任选其一或组合。
- **要求**：
  - 每引擎独立 API 客户端（`app/core/collector/{fofa,quake,...}.py`）
  - **自然语言意图翻译**：用户输入"北京的金融行业网站"，自动翻译为 FOFA 语法 `title="金融" && region="Beijing" && industry="finance"`
  - 引擎查询结果去重合并（按 host:port）
  - 引擎支持手动开关（无 API Key 时跳过该引擎）

#### R-103 【Must】LLM 漏洞验证

- **描述**：Worker 通过 LLM 调用自主选择 PoC 验证方式，LLM 返回**结构化决策**（哪个 payload、哪个工具）。
- **支持漏洞类型**：SQLi、XSS、RCE、SSRF、文件上传、未授权访问、IDOR、敏感信息泄露、组件 CVE（nuclei 模板覆盖）。
- **Prompt 模板**：附录 A。
- **依赖**：R-201（v3 安全护栏，所有验证动作必须在白名单内）。

#### R-104 【Must】Web 控制台

- **页面清单**：
  - **Dashboard / 看板**：实时扫描状态、最近 Finding、Worker 健康
  - **任务管理**：任务创建向导（自然语言输入目标）、任务列表、取消 / 重跑
  - **Finding 复审**：单条复审、批量复审、过滤、搜索
  - **Hunter-Killer 看板**：通杀任务进度、候选数、验证结果
  - **审计日志**：append-only 审计查询（按时间 / 用户 / 工具过滤）
  - **设置**：LLM 配置、引擎 Key、RBAC 用户管理
- **技术**：Vue 3 + Vite + Pinia + Element Plus + ECharts（仪表盘图表）

#### R-105 【Must】报告生成

- **格式**：Markdown / PDF / HTML / JSON 四种
- **内容**：目标信息、漏洞清单、证据、风险等级、修复建议、复审状态
- **不含截图**（v3 安全考虑，避免证据泄露）

---

### 0.3 多 Agent 协作

> **核心理念**：每个 Agent 职责单一、可独立替换、通过明确定义的接口协作。

#### R-201 【Must】Collector Agent

- **职责**：根据用户的自然语言意图，从搜索引擎拉取目标列表。
- **输入**：`"北京的金融行业网站"`（自然语言）
- **输出**：URL 列表（带引擎来源标记）
- **关键能力**：自然语言 → FOFA/Quake/etc. 语法的翻译（LLM 辅助）。

#### R-202 【Must】Worker Agent

- **职责**：单目标扫描主体，运行 ReAct 循环。
- **输入**：单个 URL
- **输出**：Finding 候选列表（提交给 Reviewer）
- **关键约束**：
  - 所有工具调用必须经过 `ToolInterceptor`（R-302）
  - 紧急熔断检查每轮执行（不可被白名单绕过）
  - 单目标 80 轮 ReAct 上限

#### R-203 【Must】Reviewer Agent

- **职责**：对 Worker 的 Finding 候选做**初筛**，决定 pass / needs_deep / reject。
- **作用**：减少噪音，把明显误报挡在前面。
- **机制**：LLM 评估证据 + 漏洞模式 + 上下文相关性。
- **输出**：
  - `pass` → 进入"待人工复审"队列
  - `needs_deep` → 触发 Hunter-Killer 通杀
  - `reject` → 进入丢弃池（仍可查询）

#### R-204 【Must】Hunter-Killer（通杀）Agent

- **职责**：当 Reviewer 通过的高危 Finding 出现后，**自动在全网寻找同款漏洞**。
- **典型流程**：
  1. 提取漏洞指纹（如"特定 Nuclei 模板 ID"、"组件版本特征"）
  2. 在搜索引擎中搜索候选目标
  3. 对每个候选目标构造相同的 PoC 验证
  4. 验证通过 → 批量新增 Finding
- **安全**：所有验证动作同样经过 `ToolInterceptor`（R-302）+ `ScopeGuard` 三层校验。

#### R-205 【Should】Agent 间协议清晰

- **要求**：Agent 之间通过**消息队列**（asyncio.Queue / DB 表）通信，不共享内存。
- **好处**：可独立重启、可水平扩展、可观察。

---

### 0.4 安全护栏（v3 核心，用户最关心的部分）

> **本节是用户最核心的需求**，源自多轮需求访谈中明确表达的安全约束。**任何 PoC / 验证 / 通杀动作都必须遵守本节规则**。

#### R-301 【Must】无害化 PoC 原则

- **理念**：每个漏洞类型都有"**标准无害化验证动作**"，证明漏洞存在但不造成真实危害。
- **LLM 决策模式**：LLM 在系统提供的"白名单 + 推荐 PoC 库"内**自主选择最合适的验证方式**；系统做边界守卫（白名单外硬拦截）。
- **不接受**：
  - 直接反弹 shell
  - 批量脱敏 / 全表导出
  - 写文件（除非 SELF 资源，见 R-304）
  - 访问云元数据（169.254.169.254）
  - 关闭 / 重启目标服务

#### R-302 【Must】RCE 验证：仅允许白名单只读命令

- **允许命令**（白名单）：
  - 身份类：`whoami`、`id`、`hostname`、`uname -a`
  - 信息收集：`cat /etc/passwd`、`cat /etc/issue`、`cat /etc/os-release`
  - 进程：`ps aux`、`ps -ef`、`ps aux | head -20`
  - 网络：`ifconfig`、`ip addr`、`cat /etc/hosts`、`nslookup www.baidu.com`
  - 时间盲注：`sleep 3`、`sleep 5`、`sleep 10`（最大 30s）
- **禁止命令**（黑名单）：
  - **反弹 shell**：`bash -i >& /dev/tcp/...`、`nc -e`、`python socket.connect`
  - **写文件**：`>`、`>>`、`tee /etc/...`
  - **删文件**：`rm`、`mv /`
  - **系统破坏**：`shutdown`、`reboot`、`mkfs`、`dd if=`
  - **远程下载执行**：`wget ... | bash`、`curl ... | sh`
  - **持久化**：`>> /root/.ssh/authorized_keys`、`> /etc/cron.*`
  - **用户管理**：`useradd`、`passwd`
- **输出限制**：单条命令输出截断至 1024 字节。

#### R-303 【Must】SSRF 验证：仅允许公网无害目标

- **允许目标**：
  - 国内：`www.baidu.com`、`www.qq.com`、`www.163.com`、`www.example.com`
  - 国际：`www.example.com`、`www.google.com`、`www.bing.com`
  - 公网 DNS：`8.8.8.8`、`1.1.1.1`、`114.114.114.114`
- **禁止目标**：
  - 私有 IP：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`
  - 云元数据：`169.254.0.0/16`
  - 内网域名：`*.internal`、`*.local`
- **协议限制**：仅允许 `http://`、`https://`，禁止 `file://`、`gopher://`、`dict://`。

#### R-304 【Must】XSS 验证：仅允许浏览器弹窗 payload

- **允许 payload**：
  - `<script>alert(1)</script>`
  - `<img src=x onerror=alert(1)>`
  - `<svg onload=alert(1)>`、`<body onload=alert(1)>`
  - `<input onfocus=alert(1) autofocus>`
- **禁止 payload**：
  - 窃取 cookie：`document.cookie`、`new Image().src='.../?c='+document.cookie`
  - 键盘记录：`addEventListener('keydown', ...)`、`addEventListener('keyup', ...)`
  - 钓鱼重定向：`window.location='http://evil.com'`、`location.href='...'`
  - 数据外传：`fetch(...)`、`XMLHttpRequest(...)`
  - 摄像头 / 麦克风：`navigator.mediaDevices.getUserMedia()`
  - 加密挖矿：`coinhive`、`cryptonight`
- **验证方式**：用 Playwright/Selenium 无头浏览器实测，捕获 dialog 事件作为证据。

#### R-305 【Must】SQLi 验证：限行数 + 不脱敏

- **取数限制**：**最多取 3 条记录**（系统自动注入 `LIMIT 3` / `TOP 3`）
- **不脱敏**：取出的数据**原样保留**作为漏洞证据（明文密码 / 邮箱等保留）
- **禁止操作**：
  - `INSERT / UPDATE / DELETE`
  - `DROP / CREATE / ALTER`
  - `LOAD_FILE()` 读文件
  - `INTO OUTFILE / INTO DUMPFILE` 写文件
  - `xp_cmdshell`、`sp_executesql`
- **适用所有数据库**：MySQL、PostgreSQL、MSSQL、Oracle、SQLite。

#### R-306 【Must】文件读取：白名单 + 限量

- **允许文件**：`/etc/passwd`、`/etc/hosts`、`/etc/issue`、`/etc/os-release`、`/proc/version`
- **禁止文件**：`/etc/shadow`、`/root/.ssh/*`、`*.key`、`*.pem`、`/proc/self/environ`
- **字节限制**：单次读取 ≤ 2048 字节（系统自动截断）。

#### R-307 【Must】资源所有权区分：SELF vs TARGET

- **SELF 资源**（平台自身上传 / 创建的文件）：
  - 路径前缀：`/tmp/hunter/`、`/var/tmp/hunter/`、`./uploads/`
  - **24 小时内**可读 / 写 / 删除（自动过期检查）
  - 用途：上传测试文件 → 验证上传漏洞 → 删除（这就是"自己的文件可以删"的来源）
- **TARGET 资源**（授权扫描目标的资源）：
  - 仅可读（GET / HEAD）
  - 严格按 R-302/303/304/305/306 的白名单
  - **禁止写 / 删任何 TARGET 文件**
- **判定逻辑**：由 `ResourceContext.from_target(url)` 在每次工具调用前解析。

#### R-308 【Must】ToolInterceptor 集中管控

- **所有工具调用必须经过 `app/security/safety/tool_interceptor.py`**。
- 任何绕过拦截器的调用都被审计为违规（`safety_denied_total` 计数 +1）。
- 拦截器实现：白名单匹配 → 黑名单硬拦截 → 自动修正（注入 LIMIT）→ 输出截断。
- **接入点**：
  - Worker ReAct 循环主入口
  - Hunter-Killer VerifierPool 验证调用
  - 任何手工触发的脚本

#### R-309 【Must】LLM 自主决策框架

- **核心理念**：不硬拦截所有"危险"动作，而是：
  1. 提供每类漏洞的"推荐无害化 PoC"清单
  2. LLM 根据漏洞上下文**自主选择**最合适的验证方式
  3. 系统做**边界守卫**（白名单 + 限速 + 限行数）
  4. 危险操作（破坏性 / SSRF 内网 / 反弹 shell）由系统**硬拦截**
- **决策验证**：系统层硬约束 + LLM 层软建议（双重验证），不合规时返回 reason 让 LLM 修改决策。

#### R-310 【Must】紧急熔断（L0 隔离下最高安全开关）

- **可由用户随时激活**（Web 按钮 + API 调用 + 命令行）。
- **不可被白名单绕过**：每个 Agent 循环的每轮都检查。
- **激活后效果**：所有 Worker 立即停止；新任务拒绝；已在执行的工具调用立即取消。
- **审计**：激活 / 取消熔断都记录到审计日志（带用户、原因、时间戳）。

#### R-311 【Should】用户协议确认

- 首次启动时显示"无害化 PoC 验证承诺"（R-302/303/304/305/306 摘要），用户勾选后方可启动 Worker。

---

### 0.5 RBAC 与审计

#### R-401 【Should】4 角色 RBAC（远期增强）

> **MVP 基线说明**：当前基线采用**环境变量令牌**鉴权（`HUNTER_API_TOKEN` 全权限 / `HUNTER_READ_TOKEN` 只读 / `HUNTER_OBSERVER_TOKEN` 观摩，见 §12.1）。本需求的"多角色 + 用户管理"为**远期增强**，升级时不得改动既有表，如需用户表只允许新增表。

| 角色 | 权限 |
|---|---|
| **admin**（管理员） | 全部权限：用户管理、配置、查看审计、激活熔断 |
| **operator**（操作员） | 创建任务、查看 Finding、复审、触发通杀 |
| **reader**（只读） | 仅查看 Finding / 报告，不能复审或触发 |
| **observer**（观摩） | 仅看 Dashboard，不能看 Finding 详情 |

- **实现（远期）**：FastAPI Depends + JWT Token + 装饰器。
- **页面**：设置 → 用户管理（admin 才能访问）。

#### R-402 【Must】append-only 审计日志

- **审计内容**：
  - 全量 API 调用（用户、时间、路径、参数、响应状态）
  - LLM 调用（prompt 摘要、模型、成本、耗时）
  - Worker 操作（每个工具调用、Finding 创建、复审动作）
  - 安全事件（拦截器拒绝、紧急熔断激活、SELF 资源过期）
- **存储（MVP 基线）**：SQLite 表 `task_events`（append-only，API 层不提供 UPDATE/DELETE），承担审计 + 实时日志职责（§4.2⑥）。远期如需独立审计表，**只允许新增表**，严禁改动既有表（§4 兼容性红线）。
- **导出**：支持按时间范围 / 事件类型查询。

#### R-403 【Should】登录与令牌（MVP 为环境变量令牌）

- **MVP 基线**：环境变量令牌 `HUNTER_API_TOKEN` / `HUNTER_READ_TOKEN` / `HUNTER_OBSERVER_TOKEN`，常量时间比对（hmac.compare_digest），见 §12.1。
- **远期增强**：用户名 + 密码（bcrypt 哈希存储）+ JWT Token，需新增用户表（红线内允许）。
- **强制**：所有 API 端点必须鉴权（除 `/api/auth/status`、`/health`）。

---

### 0.6 工具链集成

#### R-501 【Must】核心工具清单

| 工具 | 用途 | 必需 / 可选 |
|---|---|---|
| **nmap** | 端口扫描、服务识别 | 必需 |
| **nuclei** | 漏洞模板扫描（CVE / 组件） | 必需 |
| **httpx** | HTTP 探活、技术栈识别 | 必需 |
| **subfinder** | 子域名枚举 | 必需 |
| **sqlmap** | SQL 注入验证 | 必需 |
| **katana** | 爬虫、URL 发现 | 必需 |
| **ffuf** | 目录 / 文件模糊测试 | 必需 |
| **EHole / WhatCMS** | CMS 指纹 | 必需 |
| **naabu** | 端口扫描（masscan 替代） | 可选 |
| **masscan** | 高速端口扫描 | 可选 |
| **dnsx** | DNS 查询 | 可选 |
| **gau / waybackurls** | 历史 URL 收集 | 可选 |
| **dirsearch** | 目录扫描（Python 备选） | 可选 |
| **Playwright** | XSS 浏览器验证 | 可选（+300MB） |

#### R-502 【Must】工具版本固定

- 所有工具在 `Dockerfile` 和 `install_tools.sh` 中固定到具体版本（避免工具版本升级带来的 breaking change）。
- 版本记录在 `TOOLS_VERSIONS.md`。

#### R-503 【Must】nuclei 模板默认不启用 OOB

- 默认 `oob_check=false`（OOB = Out-of-Band，需 interactsh-client 外连）。
- 不安装 `interactsh-client`，避免 DNS 外连。
- 仅使用无外连的 nuclei 模板。

#### R-504 【Should】国内镜像加速

- pip：清华源
- Docker：USTC / 网易镜像
- Go proxy：goproxy.cn
- apt：阿里云镜像

---

### 0.7 部署形态

#### R-601 【Must】Docker Compose 一键部署

- 单 `docker-compose up -d` 启动。
- 数据持久化到宿主机 `./data`、`./reports`、`./logs` volume。
- 端口暴露：8080（Web 控制台）。

#### R-602 【Must】镜像体积可控

- 单阶段基础版：~2-3GB
- 多阶段优化版：~2GB（节省 200MB）
- 可选裁剪：关闭 nuclei templates（-500MB-1.5GB）/ Playwright（-300MB）/ SecLists（-1.2GB）

#### R-603 【Should】支持离线部署

- 在有网络的机器上 `docker save` 镜像 → 拷贝到目标机器 → `docker load`。
- 提供 `install_tools_offline.sh` 用于本地包安装 Go 工具。

#### R-604 【Should】Ubuntu 22.04 LTS 优先

- 官方镜像基于 Ubuntu 22.04。
- 兼容 20.04（需手动调整 Python 3.12 安装）。

#### R-605 【Could】K8s 部署

- 不在 MVP 范围，但保留扩展空间（PVC / ConfigMap / Secret）。

---

### 0.8 性能与并发

#### R-701 【Must】单机内 asyncio 并发

- 单进程内 asyncio + 线程池（CPU 密集型任务用 ProcessPoolExecutor）。
- 不引入分布式队列（Redis / Kafka / RabbitMQ）。

#### R-702 【Must】并发上限可调

- 默认 `WORKER_MAX_CONCURRENT=15`（4C8G 主机）。
- 通过环境变量调整，最大可到 50（需更大内存）。
- cgroup 软限 CPU / 内存，避免打爆主机。

#### R-703 【Must】限速

- 全局：`RATE_LIMIT_GLOBAL_RPS=200`
- 单 Worker：`RATE_LIMIT_PER_WORKER_RPS=30`
- 单目标：`RATE_LIMIT_PER_HOST_RPS=10`（避免触发目标 WAF）

#### R-704 【Must】SQLite 性能优化

- WAL 模式 + `synchronous=NORMAL` + `cache_size=-20000`
- 单机 15-30 Worker 性能足够，超过 50 Worker 需考虑 PostgreSQL。

#### R-705 【Should】LLM 成本控制

- 单目标 LLM 成本上限：`LLM_PER_TARGET_BUDGET=1.0`（USD）
- 超限后自动切换到人工复审，不再发 LLM 调用。
- 仪表盘显示成本趋势。

---

### 0.9 风险与限制

#### R-801 【Must】紧急熔断可恢复

- 紧急熔断激活后，所有数据保持一致（任务标记为 stopped，可恢复）。
- 取消熔断后，已停止的任务可手动重启。

#### R-802 【Must】审计不可篡改

- append-only 表 + SQLite 触发器禁止 UPDATE / DELETE。
- 管理员也无法删除审计日志（仅可导出）。

#### R-803 【Should】数据备份

- 每日凌晨 3 点自动备份 SQLite 到 `./backups/data_YYYYMMDD.db.gz`。
- 保留最近 30 天，可手动清理更早备份。

#### R-804 【Could】Prometheus 监控

- 暴露 `/metrics` 端点。
- 关键指标：Worker 活跃数、LLM 调用次数 / 成本 / 延迟、Finding 分布、安全拒绝次数、紧急熔断激活次数。

---

### 0.10 不在范围内

明确**不做**的事，避免范围蔓延：

- ❌ 多机分布式部署（仅单机）
- ❌ 多租户 SaaS（仅单机个人使用）
- ❌ 漏洞利用链 / 漏洞武器化（仅漏洞验证，不做利用）
- ❌ 钓鱼 / 社工（仅技术验证）
- ❌ 内网渗透（仅授权目标）
- ❌ 移动 App 漏洞（仅 Web）
- ❌ 二进制漏洞（仅 Web + 组件）
- ❌ 商业用途（仅授权研究）

---

### 0.11 需求依赖关系图

```
R-002 代码基线 ──→ R-101 Worker ReAct ──→ R-201 v3 安全护栏
                                       └─→ R-204 Hunter-Killer
                                                 │
R-001 自动化 ──→ R-201 安全护栏 ←── R-301~310      │
       │            │                              │
       │            └─→ R-302 RCE                  │
       │            └─→ R-303 SSRF                 │
       │            └─→ R-304 XSS                  │
       │            └─→ R-305 SQLi                 │
       │            └─→ R-306 文件                 │
       │            └─→ R-307 SELF/TARGET          │
       │            └─→ R-308 ToolInterceptor      │
       │            └─→ R-310 紧急熔断             │
       │                                          │
R-003 单机部署 ──→ R-601 Docker Compose ──→ R-602 镜像体积
                                            └─→ R-603 离线部署

R-201 安全 ──→ R-401 RBAC ──→ R-402 审计
                      └─→ R-403 登录令牌
```

---

### 0.12 验收优先级汇总

| 优先级 | 数量 | 代表需求 |
|---|---|---|
| **Must** | 25+ | R-001 自动化、R-101 ReAct、R-201~310 安全护栏、R-401 RBAC、R-501 工具、R-601 Docker |
| **Should** | 12+ | R-004 扩展性、R-205 Agent 协议、R-311 用户协议、R-503 不启用 OOB、R-504 国内镜像、R-603 离线、R-705 LLM 成本 |
| **Could** | 5+ | R-605 K8s、R-804 Prometheus |

**MVP 阶段**：完成全部 Must + 关键 Should，4 周交付。
**GA 阶段**：完成全部 Could，加固 + 监控。

---

## 1. 系统架构总览

```
┌──────────────────────────────────────────────────────────────────┐
│                   Hunter Pro  整体架构                       │
└──────────────────────────────────────────────────────────────────┘

            ┌─────────────────────────────────────────┐
            │  Vue 3 控制台 (SPA, port 18800)         │
            │  看板 / 任务 / 复审 / 设置 / 审计      │
            └──────────────────┬──────────────────────┘
                               │ HTTPS (Token Auth)
                               ▼
            ┌─────────────────────────────────────────┐
            │  FastAPI 网关 + 业务编排层 (单进程)     │
            │  ├── /api/v1/tasks                      │
            │  ├── /api/v1/findings                   │
            │  ├── /api/v1/workers                    │
            │  ├── /api/v1/audit                      │
            │  └── /api/v1/settings                   │
            └─────┬────────────┬─────────────┬────────┘
                  │            │             │
        ┌─────────▼─┐    ┌─────▼──────┐  ┌───▼────────┐
        │ Collector │    │  Scheduler │  │   Audit    │
        │  Agent    │    │  + Queue   │  │   Logger   │
        │ (asyncio) │    │ (asyncio)  │  │  (文件+SIEM)│
        └─────┬─────┘    └─────┬──────┘  └────────────┘
              │                │
              │   目标入队     │   派发任务
              ▼                ▼
        ┌─────────────────────────────────────────────┐
        │     Worker Pool  (最多 15 个并发)           │
        │  ┌──────┐ ┌──────┐ ┌──────┐      ┌──────┐ │
        │  │ W-01 │ │ W-02 │ │ W-03 │ ...  │ W-15 │ │
        │  └──────┘ └──────┘ └──────┘      └──────┘ │
        │  每个 Worker:                                │
        │   ① LLM Agent (ReAct loop, 80 rounds)       │
        │   ② 工具调用白名单 (subprocess)              │
        │   ③ 工具链: nmap/nuclei/httpx/whatweb/...   │
        │   ④ 结果审查 → Reviewer                      │
        └────────────────┬────────────────────────────┘
                         │
                         ▼
            ┌─────────────────────────────┐
            │  Reviewer Agent + 通杀      │
            │  Hunter + 情报库            │
            └─────────────┬───────────────┘
                          │
                          ▼
            ┌─────────────────────────────┐
            │  报告生成 + 人工复审 UI     │
            └─────────────────────────────┘
                          │
                          ▼
            ┌─────────────────────────────┐
            │  SQLite (WAL) + 数据卷      │
            │  ├── tasks / targets        │
            │  ├── findings / reviews     │
            │  ├── killsweeps / intel     │
            │  ├── task_events            │
            │  └── system_settings        │
            └─────────────────────────────┘
```

### 关键数据流

1. **任务创建** → Collector Agent 调 FOFA/Quake/... → 目标清单 → SQLite
2. **任务调度** → Scheduler 从队列取目标 → 派发到空闲 Worker
3. **挖洞执行** → Worker 内的 LLM Agent (ReAct) 调工具链 → 生成候选漏洞
4. **AI 初审** → Reviewer Agent 过滤半成品/误报 → 标记"够格"的洞
6. **通杀扫描** → 通杀 Hunter 取够格的洞 → 验证同款 → 一打一片
7. **人工复审** → 控制台显示 → 用户通过/打回/编辑
8. **报告生成** → 通过的洞 → 模板渲染 → Markdown/PDF/HTML/JSON

---

## 2. 技术栈选型

| 层 | 选型 | 版本 | 说明 |
|---|---|---|---|
| 运行时 | Python | 3.12 | asyncio 结构化并发 |
| Web 框架 | FastAPI | 0.115+ | OpenAPI 自动生成 |
| ORM | SQLAlchemy | 2.0 (async) | 配合 aiosqlite |
| 数据库 | SQLite (WAL) | 3.45+ | 单机足够；预留 PG 切换 |
| 任务队列 | asyncio.Queue | 内置 | 不引入 Celery（单机够用） |
| HTTP 客户端 | httpx | 0.27+ | async/await + HTTP/2 |
| LLM SDK | openai / anthropic | latest | 统一封装 `LLMClient` |
| 工具封装 | 自研 `ToolRegistry` | - | 白名单 + 二次确认 |
| 配置 | pydantic-settings | 2.x | `.env` + DB 双源 |
| 日志 | loguru | 0.7+ | 结构化 + JSON 适配 |
| 前端 | Vue 3 + Vite | 3.5 / 5.x | SPA + TS |
| UI 库 | Element Plus | 2.x | 看板 + 表格 + 表单 |
| 状态管理 | Pinia | 2.x | |
| HTTP 客户端 | axios | 1.x | 拦截器注入 Token |
| 图表 | ECharts | 5.x | 仪表盘 |
| 容器 | Docker + Compose v2 | 24+ | |
| 反向代理 | Nginx / Caddy | - | 生产环境推荐 |

---

## 3. 目录结构

> 目录结构为自有代码基线（R-002）沉淀而成，与既有代码保持同构。以下为实际基线结构。

```
Hunter/
├── app/                        # 后端代码（自有基线）
│   ├── __init__.py
│   ├── main.py                 # FastAPI 入口（品牌: Hunter）
│   ├── config.py               # 配置 (pydantic-settings, .env)
│   ├── orchestrator.py         # 任务编排器
│   ├── agent_runtime.py        # Agent 运行时
│   ├── dedup.py                # Finding 去重
│   ├── events.py               # 事件推送
│   ├── schemas.py              # Pydantic Schema
│   ├── security.py             # Token 鉴权
│   ├── settings_service.py     # 设置服务
│   ├── urlnorm.py              # URL 规范化
│   ├── waf.py                  # 应用层 WAF
│   ├── workdir_cleanup.py      # 工作目录清理
│   │
│   ├── agents/                 # ReAct Agents
│   │   ├── attacker.py         # Attacker Agent（核心攻击）
│   │   ├── recon.py            # Recon 侦察 / 目标采集
│   │   ├── auditor.py          # Auditor 极理性初审
│   │   ├── sweeper.py          # 通杀验证
│   │   ├── explore.py          # 深化挖掘
│   │   ├── escalate.py         # 权限提升
│   │   ├── knowledge.py        # 情报沉淀
│   │   ├── prefilter.py        # 预过滤
│   │   ├── scorer.py           # 评分
│   │   ├── scope_gate.py       # 目标范围闸门
│   │   ├── seed_targets.py     # 手工目标清洗
│   │   ├── prompts.py          # Prompt 模板
│   │   └── ...                 # 其余辅助 Agent
│   │
│   ├── api/                    # API 路由
│   │   ├── tasks.py            # 任务管理
│   │   ├── findings.py         # Finding 复审
│   │   ├── intel.py            # 情报库
│   │   ├── settings.py         # 设置
│   │   ├── stream.py           # 流式日志
│   │   ├── vulns.py            # 漏洞视图
│   │   ├── runtime_logs.py     # 运行时日志
│   │   ├── update.py           # 更新
│   │   └── dto.py
│   │
│   ├── db/                     # 持久层（schema 自有基线，100% 固定）
│   │   ├── models.py           # 表模型（UUID 主键）
│   │   └── session.py          # aiosqlite 会话
│   │
│   ├── engines/                # 目标采集引擎
│   │   ├── fofa.py / quake.py / hunter.py / zoomeye.py / shodan.py / censys.py
│   │   ├── sync.py / translator.py / base.py
│   │
│   ├── llm/                    # LLM 客户端
│   │   ├── client.py / health.py / usage.py
│   │
│   ├── tools/                  # 工具白名单（供 Attacker 调用）
│   │   ├── executor.py / guard.py / netguard.py / decoder.py / js_analyzer.py / cred_leak.py ...
│   │
│   ├── fofa/                   # FOFA 查询客户端
│   ├── maintenance/            # 维护任务
│   └── data_static/            # 静态数据（edu_ip.db 等）
│
├── frontend/                   # Vue 3 前端（品牌: Hunter）
│   ├── src/
│   │   ├── main.js / App.vue / api.js / report.js / format.js
│   │   ├── views/              # Dashboard / Tasks / Findings / Settings ...
│   │   ├── components/         # UI 组件
│   │   └── composables/
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── tools/                      # 自带工具扩展（owner_db_builder 等）
├── scripts/                    # 部署脚本
│   ├── setup.sh              # 一键安装（Docker）
│   ├── boot.sh    # 看门狗启动
│   └── ...
├── tests/                      # 测试
├── web/                        # Web 静态资源（构建产物）
│
├── data/                       # 运行时数据（volume 挂载 /app/data）
│   └── hunter.db           # SQLite 主库（同名同构，R-005 自动采用）
│
├── docs/                       # 文档
├── .env.example                # 环境变量模板
├── docker-compose.yml          # 容器编排（volume: hunter_data:/app/data, hunter_work:/work）
├── Dockerfile                  # 后端镜像
├── requirements.txt
├── README.md
└── LICENSE
```

---

## 4. 数据模型与持久层

> **⚠️ 兼容性红线（R-005）**：Hunter 直接使用旧部署的 `hunter.db`，数据库 schema **100% 固定**（表名、字段、UUID 主键、`hunter.db` 文件名、`/app/data` 挂载路径）。**只允许新增表 / 新增列（必须带 DEFAULT），严禁修改、删除、重命名任何既有表或列**。完整约束见 §21。

### 4.1 ER 概览（固定表结构）

```
Task ──< Target ──< Finding ──1:1── Review
  │        │           │
  │        │           └── Killsweep.origin_finding_id ──> Killsweep（通杀，产品指纹去重）
  │        │
  │        └── (status / assigned_worker / heartbeat_at) 24x7 状态机
  │
  └── TaskEvent（审计 + 实时日志，append-only，自增 id）

Intel（全局情报库，跨任务共享：cred / fingerprint / endpoint / profile）
SystemSettings（单行 id='global'：llm / fofa / engines / defaults）

鉴权：不走 DB 用户表，采用环境变量令牌（HUNTER_API_TOKEN 等，见 §12）
```

### 4.2 核心表结构（8 张表）

> 模型定义以 `app/db/models.py` 为**唯一事实来源**（现有代码，无需重写）。下面列出每张表的关键列与用途，DDL 均由 SQLAlchemy 自动生成，主键统一为 **UUID `String(32)`**（`uuid.uuid4().hex`），时间统一为 **UTC naive `DateTime`**（前端经 `to_cst_iso()` 转东八区显示）。

**① `tasks` — 挖掘任务（一个任务 = 一个资产范围）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | UUID |
| `name` | String(200) | 任务名 |
| `src_type` | String(20) | 任务类型，默认 `edusrc` |
| `vuln_types` | JSON | 选定漏洞类型列表 |
| `src_rules` | Text | 附加 SRC 规则（叠加内置标准） |
| `target_source` | String(20) | `fofa` / `manual` / `both` / `site` |
| `fofa_query` / `manual_targets` | Text / JSON | 目标来源配置 |
| `auth_bindings` | JSON | 用户登录凭据绑定列表 |
| `model_config` / `fofa_config` | JSON | LLM 模型配置 / FOFA 翻页配置 |
| `engine` | String(20) | 搜索引擎：fofa/quake/hunter/zoomeye/shodan/censys |
| `concurrency` | Integer | worker 并发数，默认 3 |
| `status` | String(20) | created / running / paused / stopped / idle |
| `created_at` / `updated_at` | DateTime | 审计时间戳 |

**② `targets` — 目标（host 级，去重键 `(task_id, host, source)`）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | UUID |
| `task_id` | FK → tasks.id | 所属任务 |
| `url` / `host` | String | 目标 URL / 去重键 |
| `ip` / `org` / `title` / `school` | String | 资产信息（school=候选归属学校） |
| `source` | String(20) | fofa / manual |
| `is_edu` | Boolean | 是否教育行业 |
| `priority_score` / `priority_reason` | Float / String | 优先级评分（决定 worker 先打谁） |
| `status` / `verdict` | String(20) | queued/assigned/scanning/done/skipped/dead；found/no_vuln/error |
| `retry_count` / `dead_reason` / `last_error` | Int / String | 重试与硬骨头库（终态原因审计） |
| `deepen_context` / `deepen_count` | JSON / Int | 审核打回深挖上下文与次数（防死循环） |
| `leaked_creds` / `auth_context` / `auth_status` | JSON | 泄露凭证 / 用户凭据 / 凭据使用反馈 |
| `assigned_worker` / `heartbeat_at` | String / DateTime | 派发 worker 与心跳（24x7 恢复） |

**③ `findings` — 漏洞（worker 产出，去重键 `dedup_key` 全局唯一）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | UUID |
| `task_id` / `target_id` / `worker_id` | FK / FK / String | 归属 |
| `vuln_type` / `title` / `severity_claimed` | String | 类型 / 标题 / 自报等级 |
| `target_url` / `owner` | String | 目标 URL / 归属单位（学校）+确认依据 |
| `description` / `steps` / `poc` | Text / JSON / Text | 描述 / 复现步骤 / PoC |
| `raw_request` / `raw_response` / `evidence` | Text / Text / JSON | 原始请求包 / 响应 / 证据 |
| `affected_scope` / `kill_chain` / `assistant_messages` | Text / JSON / JSON | 影响范围 / 攻击链路 / 报告助手对话 |
| `self_check` | JSON | 自查结果 |
| `dedup_key` | String(128) | 漏洞级去重（全局唯一索引） |
| `llm_model` / `llm_base_url` | String | 实际打出该洞的模型与端点（归因） |
| `status` | String(20) | pending_review / reviewed |

**④ `reviews` — 审核（Finding 1:1，AI 初审 + 用户复审）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | UUID |
| `finding_id` | FK → findings.id (unique) | 唯一对应 |
| `verdict` / `confidence` | String(20) | accepted/ignored/deepen；confirmed/likely/uncertain |
| `severity_final` / `score` | String / Float | 终审等级 / 评分 |
| `in_scope` / `is_duplicate` / `reproduced` | Boolean | 范围 / 重复 / 复现 |
| `ignore_reasons` / `downgrade_reasons` | JSON | 忽略 / 降级原因 |
| `reviewer_notes` / `deepen_directive` | Text | AI 备注 / 深挖指令 |
| `user_status` / `user_severity` / `user_notes` | String / String / Text | 用户复审：pending/passed/rejected |
| `user_edits` | JSON | 用户编辑后的报告内容（覆盖原值） |
| `submitted` / `user_reviewed_at` | Boolean / DateTime | 是否已提交 SRC |

**⑤ `killsweeps` — 通杀分析（产品指纹去重，同任务同 `product_key` 只一条）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | UUID |
| `origin_finding_id` / `product_key` / `product_name` | String | 触发洞 / 产品指纹去重键 / 产品名 |
| `vuln_type` / `vuln_summary` / `fofa_query` | String / Text / Text | 通杀漏洞说明与圈定语法 |
| `fingerprint` / `asset_count` / `edu_count` | Text / Int / Int | 指纹依据 / 全网规模 / 教育行业规模 |
| `is_killsweep` / `confidence` | Boolean / String | 是否可通杀 / 置信度 |
| `verified_url` / `verified` | String / Boolean | 实际验证的同款站点 |
| `affected_table` | JSON | 通杀影响明细表 |
| `status` | String(20) | analyzing / done / failed |

**⑥ `task_events` — 审计 + 实时日志（append-only，自增主键）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | Integer PK autoincrement | **唯一一张自增主键表**（回放排序用） |
| `task_id` | FK → tasks.id | 所属任务 |
| `agent` / `level` / `kind` | String | orchestrator/collector/worker/reviewer；info/warn/error；事件类型 |
| `message` / `payload` | Text / JSON | 消息正文 / 结构化载荷 |
| `ts` | DateTime | 时间戳（索引） |

**⑦ `intel` — 全局情报库（跨任务共享，单表四类）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | UUID |
| `kind` | String(20) | cred / fingerprint / endpoint / profile |
| `match_key` / `dedup_hash` | String | 检索键（root 域/指纹）/ 内容指纹（去重） |
| `payload` / `summary` | JSON / String | 情报内容 / 一句话摘要（注入 prompt 用） |
| `source_host` / `source_task_id` | String | 贡献来源 |
| `confidence` | String(20) | verified（出洞验证）/ likely（声称有效） |
| `hit_count` / `first_seen` / `last_seen` | Int / DateTime / DateTime | 命中次数（越高越可信） |

**⑧ `system_settings` — 全局系统配置（单行 id='global'）**

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | String(32) PK | 固定 `global` |
| `llm` / `fofa` / `engines` / `defaults` | JSON | 全局默认配置（任务级可覆盖） |
| `updated_at` | DateTime | 更新时间 |

### 4.3 持久层约定（app/db/session.py，现有代码）

- **连接**：`sqlite+aiosqlite` 异步引擎，`DB_PATH` 由环境变量 `DB_PATH` 覆盖，默认 `<项目根>/data/hunter.db`（容器内即 volume 挂载点 `/app/data/hunter.db`，R-005）。
- **WAL 模式**：`PRAGMA journal_mode=WAL`，启动时统一设置。
- **连接级 PRAGMA**（每条约连接都生效）：`busy_timeout=5000`、`synchronous=NORMAL`、`foreign_keys=ON`、`cache_size=-64000`（约 64MB 页缓存）、`mmap_size=256MB`、`temp_store=MEMORY`、`wal_autocheckpoint=1000`——24x7 高并发下缓解 SQLite 锁竞争。
- **连接池**：`pool_size=20 / max_overflow=40 / pool_timeout=60`（orchestrator 多 worker + heartbeat + 看板并发远超默认 15 条连接）。
- **启动自动迁移（`init_db()`）**，顺序为：
  1. `Base.metadata.create_all` —— 建缺失的新表（老表已存在则跳过，不会改动）；
  2. `_auto_migrate` —— 按 `_MIGRATIONS` 列表对缺失列执行 `ALTER TABLE ... ADD COLUMN ...`（**带 DEFAULT，老数据零影响**）；并清理 `_DROP_COLUMNS` 中的废弃残留列（新 SQLite 支持 DROP COLUMN，失败不阻断）；
  3. `_ensure_unique_indexes` —— 补建唯一索引（`ux_targets_task_host`、`ux_findings_dedup_global`），老库已有旧形态索引的先删后建，历史数据有重复时降级为普通索引兜底；
  4. `_ensure_secondary_indexes` —— 补建看板/派发/查重热点的复合索引（失败不阻断启动）。
- **审计**：无独立 `audit_log` 表，`task_events` 承担审计 + 实时日志职责（append-only：API 层不提供 UPDATE/DELETE）。

> 上述 1-4 步正是 R-005「复制旧数据卷即可用」的机制：老库无需人工处理，启动时自动补齐缺失列与索引。**严禁**改动 `app/db/models.py` 中既有表定义。

---

## 5. 多 Agent 协同设计

### 5.1 Agent 总览

| Agent | 数量 | 输入 | 输出 | 模型建议 |
|---|---|---|---|---|
| **Collector** | 1（可水平） | 任务配置 (FOFA语法 / 自然语言) | 目标清单 (Target 表) | 小模型（Haiku/Haiku-3.5）即可 |
| **Translator** | 1（Collector 子模块） | 自然语言意图 | FOFA 语法 | 小模型 |
| **Worker (挖洞)** | 1..15 | Target URL | Finding 候选 + LLMTrace + ToolCall | 主模型（DeepSeek-V3 / Sonnet） |
| **Reviewer (初审)** | 1 | Finding 候选 | `passed` / `needs_deep` / `rejected` + 评分 | 强推理（Sonnet/Opus） |
| **Hunter-Killer (通杀)** | 1 | 已通过 Finding | 同款验证结果 | 主模型 |
| **Reporter** | 模板引擎 | Finding + 元数据 | Markdown/HTML/PDF/JSON | 模板渲染 |

### 5.2 Collector Agent

```python
# app/core/collector/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class CollectedTarget:
    url: str
    host: str
    ip: str
    port: int
    title: str = ""
    server: str = ""
    org: str = ""
    cert_org: str = ""
    country: str = ""
    asn: str = ""
    tech: list[str] = None
    fofa_score: float = 0.0
    raw: dict = None

class Collector(ABC):
    name: str

    @abstractmethod
    async def search(self, query: str, max_results: int = 100) -> list[CollectedTarget]:
        ...

    @abstractmethod
    async def translate_intent(self, intent: str) -> str:
        """自然语言 → 本引擎原生语法"""
        ...
```

### 5.3 自然语言意图 → FOFA 翻译

```python
# app/core/collector/translator.py
TRANSLATOR_PROMPT = """你是 FOFA 语法专家，将用户自然语言描述翻译为 FOFA 查询语句。
只输出 FOFA 查询本身，不要解释。

支持的字段：title=, body=, domain=, host=, org=, cert.subject.org=, port=, country=, icon=, header=

示例：
用户：找全国高校统一身份认证登录系统
输出：body="统一身份认证" && domain="edu.cn"

用户：找带管理后台的 Jupyter Notebook
输出：title="Jupyter" && body="Login"

用户：找使用 Log4j 的 Java 应用
输出：body="log4j" && server="Apache"

用户：{intent}
输出："""
```

### 5.4 多引擎适配

```python
# app/core/collector/fofa.py
class FofaCollector(Collector):
    name = "fofa"

    def __init__(self, api_key: str, base_url: str = "https://fofa.info"):
        self.api_key = api_key
        self.base_url = base_url

    async def search(self, query: str, max_results: int = 100) -> list[CollectedTarget]:
        """FOFA 原生语法直发"""
        params = {
            "qbase64": base64.b64encode(query.encode()).decode(),
            "size": min(max_results, 10000),
            "fields": "host,ip,port,title,server,org,country,asn",
        }
        # 带签名
        ...
```

```python
# app/core/collector/quake.py
class QuakeCollector(Collector):
    """Quake 需要翻译：FOFA → Quake"""

    TRANSLATION_MAP = {
        "title=": "title:",
        "body=": "body:",
        "domain=": "domain:",
        "host=": "host:",
        "&&": " AND ",
        "||": " OR ",
        "=": ":",
    }

    async def search(self, query: str, max_results: int = 100) -> list[CollectedTarget]:
        # 1. 判断是否为 FOFA 语法 → 翻译
        if self._looks_like_fofa(query):
            native_query = self._translate_fofa_to_quake(query)
        else:
            native_query = query
        # 2. 请求 Quake API
        ...
```

### 5.5 Worker ReAct Agent

```python
# app/core/worker/agent.py
from dataclasses import dataclass, field
from enum import Enum

class AgentState(str, Enum):
    THINK = "think"
    ACT = "act"
    OBSERVE = "observe"
    FIND = "find"
    DONE = "done"
    DEAD = "dead"

@dataclass
class AgentStep:
    round: int
    state: AgentState
    thought: str = ""
    action: str = ""
    action_input: dict = field(default_factory=dict)
    observation: str = ""

class WorkerAgent:
    def __init__(self, target: CollectedTarget, llm: LLMClient,
                 tools: ToolRegistry, max_rounds: int = 80):
        self.target = target
        self.llm = llm
        self.tools = tools
        self.max_rounds = max_rounds
        self.history: list[AgentStep] = []
        self.findings: list[Finding] = []
        self.killed = False

    async def run(self) -> list[Finding]:
        """主循环：ReAct + 自我反思"""
        system_msg = self._build_system_prompt()
        messages = [{"role": "system", "content": system_msg}]

        for round_n in range(1, self.max_rounds + 1):
            if self.killed:
                break

            # 1. LLM 思考 + 决定下一步
            response = await self.llm.chat(messages)
            step = self._parse_response(response, round_n)
            self.history.append(step)

            if step.state == AgentState.DONE:
                break

            # 2. 执行动作
            if step.action:
                # 二次确认检查
                if self.tools.needs_confirm(step.action):
                    confirmed = await self._request_user_confirm(step)
                    if not confirmed:
                        self.history.append(AgentStep(
                            round=round_n, state=AgentState.OBSERVE,
                            observation="User denied the action. Try another approach."
                        ))
                        continue

                # 工具调用
                tool_result = await self.tools.execute(
                    step.action, step.action_input, timeout=120
                )
                step.observation = tool_result.output[:8000]

            # 3. 检查是否发现漏洞
            if self._detect_finding_in_response(response):
                finding = self._extract_finding(response)
                self.findings.append(finding)

            # 4. 自我反思（每 10 轮）
            if round_n % 10 == 0:
                reflection = await self._self_reflect(messages)
                messages.append({"role": "user", "content": reflection})

        return self.findings

    def _build_system_prompt(self) -> str:
        # 详见附录 A
        return WORKER_SYSTEM_PROMPT.format(target=self.target)

    async def _self_reflect(self, messages):
        """每 10 轮让 LLM 反思进度，避免死循环"""
        reflection_prompt = f"""回顾过去 {len(self.history)} 轮行动：
- 是否发现任何漏洞？
- 是否在重复无效操作？
- 下一步最应该做什么？

简洁回答：当前进度 + 下一步计划"""
        resp = await self.llm.chat(messages + [
            {"role": "user", "content": reflection_prompt}
        ])
        return resp.content
```

### 5.6 任务调度与 Worker Pool

```python
# app/core/worker/pool.py
import asyncio
from contextlib import asynccontextmanager

class WorkerPool:
    def __init__(self, llm_pool: LLMPool, tools: ToolRegistry,
                 max_workers: int = 15):
        self.llm_pool = llm_pool
        self.tools = tools
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
        self.active_workers: dict[str, WorkerAgent] = {}

    async def submit(self, target: Target, task: Task) -> Finding:
        async with self.semaphore:
            worker_id = f"W-{len(self.active_workers) % self.max_workers:02d}"
            self.active_workers[worker_id] = None

            # 探活
            if not await self._quick_probe(target.url):
                target.status = "unreachable"
                return None

            # 创建 Agent
            llm = self.llm_pool.acquire()
            agent = WorkerAgent(
                target=target, llm=llm, tools=self.tools,
                max_rounds=task.max_rounds or 80
            )
            self.active_workers[worker_id] = agent

            try:
                findings = await agent.run()
                # Reviewer 初审
                reviewer = ReviewerAgent(self.llm_pool.acquire())
                passed = await reviewer.review(findings, target)
                return passed
            finally:
                del self.active_workers[worker_id]
                self.llm_pool.release(llm)
```

### 5.7 Reviewer Agent

```python
# app/core/reviewer/agent.py
REVIEWER_PROMPT = """你是安全研究员，负责审查 AI 挖洞 Agent 提交的结果。

判定标准：
- ✅ PASS：可稳定复现 + 实际危害 + 证据完整
- ⚠️ NEEDS_DEEP：疑似漏洞但证据不充分，需深挖
- ❌ REJECT：误报/扫描器误判/无危害/路径不存在

输入：候选漏洞 (vuln_type, payload, evidence, reproduction, impact)
输出：JSON {verdict: pass/needs_deep/reject, score: 0-10, reason: "..."}

特别注意：
- "未授权访问" 需提供实际可访问的受限资源URL + 响应内容
- "SQL注入" 需提供具体的 SQL 错误或数据提取证据
- "Captcha Bypass" 需提供实际绕过步骤
- nuclei 模板扫描结果需验证是否真的命中（不是误报）"""
```

---

## 6. 工具链与执行沙箱

### 6.1 工具清单与白名单

```python
# app/core/worker/tools/registry.py
class ToolRegistry:
    ALLOWED_TOOLS = {
        # 侦察类
        "nmap", "httpx", "whatweb", "ehole", "naabu", "masscan",
        # 指纹/情报
        "subfinder", "katana", "gau", "waybackurls",
        # 路径爆破
        "ffuf", "dirsearch",
        # 漏洞扫描
        "nuclei",
        # 基础
        "curl", "wget",
    }

    # 危险工具：需二次确认
    NEEDS_CONFIRM = {
        "nuclei",  # 可能触发 OOB payload
    }

    # 黑名单：永远禁止
    BLACKLIST = {
        "rm", "mkfs", "dd", "nc", "ncat", "telnet",
        "bash", "sh", "zsh", "powershell",
        "curl_post_data_with_@file",  # 防止任意文件读取
    }
```

### 6.2 工具封装示例（nmap）

```python
# app/core/worker/tools/nmap.py
from .base import Tool, ToolResult
import asyncio

class NmapTool(Tool):
    name = "nmap"
    description = "端口扫描与服务识别"
    timeout = 300

    SCHEMA = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标 IP 或域名"},
            "ports": {"type": "string", "description": "端口范围，如 80,443,1-1024", "default": "top100"},
            "scripts": {"type": "string", "description": "NSE 脚本，空=禁用"},
            "service_detection": {"type": "boolean", "default": True},
            "os_detection": {"type": "boolean", "default": False},
        },
        "required": ["target"]
    }

    async def execute(self, args: dict) -> ToolResult:
        # 白名单校验
        self._check_whitelist(args["target"])

        cmd = ["nmap", "-Pn", "--max-retries", "2", "--max-rtt-timeout", "5s"]
        if args.get("service_detection"):
            cmd += ["-sV", "--version-intensity", "5"]
        if args.get("os_detection"):
            cmd.append("-O")
        if args.get("scripts"):
            cmd += ["--script", args["scripts"]]
        cmd += ["-p", args.get("ports", "top100")]
        cmd.append(args["target"])

        # 限速：通过 cgroup 实现
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024 * 10,  # 10MB
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            return ToolResult(
                success=proc.returncode == 0,
                output=stdout.decode(errors="replace"),
                error=stderr.decode(errors="replace"),
                exit_code=proc.returncode
            )
        except asyncio.TimeoutError:
            proc.kill()
            return ToolResult(success=False, output="", error="timeout", exit_code=-1)
```

### 6.3 nuclei 集成（带 OOB 安全）

```python
# app/core/worker/tools/nuclei.py
class NucleiTool(Tool):
    name = "nuclei"
    description = "nuclei 模板化漏洞扫描"
    timeout = 600

    SCHEMA = {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "templates": {"type": "array", "items": {"type": "string"}},
            "severity": {"type": "array", "items": {
                "enum": ["info", "low", "medium", "high", "critical", "unknown"]
            }},
            "tags": {"type": "array", "items": {"type": "string"}},
            "exclude_tags": {"type": "array", "items": {"type": "string"}},
            "rate_limit": {"type": "integer", "default": 60},
            "oob_check": {"type": "boolean", "default": False},  # 默认禁用 OOB
        }
    }

    async def execute(self, args: dict) -> ToolResult:
        cmd = ["nuclei",
               "-u", args["target"],
               "-jsonl",
               "-rate-limit", str(args.get("rate_limit", 60)),
               "-bulk-size", "10",
               "-c", "10",
               "-timeout", "10"]

        # 模板选择
        if args.get("templates"):
            for t in args["templates"]:
                cmd += ["-t", t]
        else:
            cmd.append("-t")  # 全部

        if args.get("severity"):
            cmd += ["-severity", ",".join(args["severity"])]
        if args.get("tags"):
            cmd += ["-tags", ",".join(args["tags"])]

        # OOB 默认禁用
        if not args.get("oob_check"):
            cmd += ["-disable-ollama"]  # 同时禁用 ollama 避免误连

        # 模板更新（首次）
        ...
```

### 6.4 限速与 cgroup

```python
# app/core/rate_limit.py
import asyncio
from collections import defaultdict

class TokenBucket:
    def __init__(self, rate: int, capacity: int):
        self.rate = rate        # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last = asyncio.get_event_loop().time()
        self.lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1):
        async with self.lock:
            now = asyncio.get_event_loop().time()
            self.tokens = min(
                self.capacity,
                self.tokens + (now - self.last) * self.rate
            )
            self.last = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            # 等待
            wait = (tokens - self.tokens) / self.rate
            await asyncio.sleep(wait)
            self.tokens -= tokens
            return True


class GlobalRateLimiter:
    """全局 + 每 Worker + 每目标 三层限速"""

    def __init__(self, rps: int = 60):
        self.global_bucket = TokenBucket(rps * 15, rps * 15 * 2)
        self.worker_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rps, rps * 2)
        )
        self.target_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rps // 4, rps // 2)
        )
```

```python
# app/core/worker/tools/base.py - 注入 cgroup
def _apply_cgroup(pid: int):
    """为子进程设置 cgroup 资源限制（L0 隔离）"""
    try:
        # 仅 Linux 容器内有效
        cgroup = f"/sys/fs/cgroup/hunter/worker_{pid}"
        os.makedirs(f"{cgroup}/memory", exist_ok=True)
        with open(f"{cgroup}/memory/memory.limit_in_bytes", "w") as f:
            f.write("4294967296")  # 4GB
        with open(f"{cgroup}/cpu/cpu.cfs_quota_us", "w") as f:
            f.write("100000")  # 1 核
        with open(f"{cgroup}/cgroup.procs", "w") as f:
            f.write(str(pid))
    except (PermissionError, FileNotFoundError):
        pass  # 容器外/非 root 跳过
```

---

## 7. 目标采集与多引擎适配

### 7.1 引擎适配矩阵

| 引擎 | API Key 配置 | 原生语法 | FOFA 翻译 | 实现位置 |
|---|---|---|---|---|
| FOFA | `FOFA_KEY` | FOFA | 直发 | `collector/fofa.py` |
| 360 Quake | `QUAKE_KEY` | Lucene-like | 需要翻译 | `collector/quake.py` |
| Hunter | `HUNTER_KEY` | 自研 | 需要翻译 | `collector/hunter.py` |
| ZoomEye | `ZOOMEYE_KEY` | 自研 | 需要翻译 | `collector/zoomeye.py` |
| Shodan | `SHODAN_KEY` | 自研 | 需要翻译 | `collector/shodan.py` |
| Censys | `CENSYS_KEY` | 自研 | 需要翻译 | `collector/censys.py` |

### 7.2 语法翻译器（FOFA → 各引擎）

```python
# app/core/collector/translator.py
class SyntaxTranslator:
    """FOFA 语法 → 各引擎原生语法"""

    @staticmethod
    def to_quake(fofa: str) -> str:
        """FOFA: body="管理" && org="CERNET" → Quake: body:"管理" AND org:"CERNET" """
        result = fofa
        # 字段映射
        result = re.sub(r'(\w+)=', r'\1:', result)
        # 逻辑符映射
        result = result.replace("&&", " AND ").replace("||", " OR ")
        # 引号保留
        return result

    @staticmethod
    def to_hunter(fofa: str) -> str:
        """FOFA → Hunter"""
        result = fofa
        result = re.sub(r'title=', 'web.title=', result)
        result = re.sub(r'body=', 'web.body=', result)
        result = re.sub(r'domain=', 'domain.suffix=', result)
        result = result.replace("&&", " && ").replace("||", " || ")
        return result

    @staticmethod
    def to_zoomeye(fofa: str) -> str:
        result = fofa
        result = re.sub(r'title=', 'title=', result)
        result = re.sub(r'body=', 'body=', result)
        result = re.sub(r'domain=', 'site=', result)
        result = result.replace("&&", " + ").replace("||", " | ")
        return result
```

### 7.3 手动清单导入

```python
# app/core/collector/manual.py
def parse_manual_targets(content: str) -> list[CollectedTarget]:
    """支持 txt / csv / json 三种格式"""
    targets = []
    lines = content.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # csv: url,priority,note
        if "," in line:
            parts = line.split(",", 2)
            url = parts[0].strip()
            priority = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 5
        else:
            url = line
            priority = 5
        # 补全 scheme
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        targets.append(CollectedTarget(
            url=url, host=urlparse(url).hostname, port=urlparse(url).port,
            priority=priority
        ))
    return targets
```

---

## 8. 漏洞检测引擎

### 8.1 漏洞类型清单

| vuln_type | 主要工具 | Prompt 重点 |
|---|---|---|
| `sqli` | nuclei + LLM 验证 | 错误型/盲注/时间型区分；payload 多样化 |
| `xss` | nuclei + LLM 验证 | 反射型/存储型/DOM 型 |
| `rce` | nuclei + LLM 验证 | 命令注入/反序列化/表达式注入 |
| `unauthorized_access` | nuclei + 手动访问 | 默认口令/未授权 API/管理后台 |
| `file_upload` | nuclei + LLM 验证 | 扩展名绕过/MIME 绕过/内容检测 |
| `idor` | nuclei + LLM 横向测试 | 参数替换/权限绕过 |
| `captcha_bypass` | nuclei + LLM 验证 | 验证码识别/客户端校验/重放 |
| `component_cve` | **nuclei 模板库** | 依赖指纹 + CVE 匹配 |

### 8.2 nuclei 模板自动加载

```python
# app/core/worker/tools/nuclei.py
class NucleiTemplateManager:
    def __init__(self, templates_dir: str = "/data/nuclei-templates"):
        self.dir = templates_dir

    async def ensure_latest(self):
        """首次启动时下载/更新 nuclei 模板（1-3GB）"""
        if not os.path.exists(self.dir):
            subprocess.run(["nuclei", "-update-templates", "-ud", self.dir])
        else:
            # 仅更新，不删除自定义模板
            subprocess.run(["nuclei", "-update-templates"])

    def filter_by_vuln_type(self, vuln_type: str) -> list[str]:
        """按漏洞类型筛选模板"""
        # 例如：sqli → nuclei-templates/vulnerabilities/sqli/*.yaml
        path = f"{self.dir}/vulnerabilities/{vuln_type}"
        if os.path.exists(path):
            return glob(f"{path}/*.yaml") + glob(f"{path}/*.yml")
        return []

    def filter_by_cve(self, cve_id: str) -> list[str]:
        """按 CVE 筛选模板"""
        return glob(f"{self.dir}/**/*{cve_id}*.yaml", recursive=True)
```

### 8.3 LLM 漏洞验证流程

```
LLM Agent → 选定 vuln_type + 候选 endpoint
        ↓
    调用 nuclei → 拿到候选命中
        ↓
    二次验证（LLM）：解析 HTTP 响应、确认漏洞特征
        ↓
    生成 Finding (含 evidence / reproduction / impact / remediation)
        ↓
    提交 Reviewer
```

---

## 9. LLM 集成与多供应商池

### 9.1 LLMClient 抽象

```python
# app/core/worker/llm_client.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator

@dataclass
class LLMResponse:
    content: str
    tool_calls: list[dict] = None
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    model: str = ""

class LLMClient(ABC):
    @abstractmethod
    async def chat(self, messages: list[dict], **kwargs) -> LLMResponse: ...

    @abstractmethod
    async def stream_chat(self, messages: list[dict]) -> AsyncIterator[str]: ...

    @abstractmethod
    def count_tokens(self, text: str) -> int: ...

    @abstractmethod
    def get_cost(self, tokens_in: int, tokens_out: int) -> float: ...
```

### 9.2 OpenAI 兼容实现

```python
# app/core/worker/llm_client.py
from openai import AsyncOpenAI

class OpenAIClient(LLMClient):
    def __init__(self, api_key: str, base_url: str, model: str,
                 protocol: str = "openai_chat"):
        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.protocol = protocol

    async def chat(self, messages, tools=None, **kwargs) -> LLMResponse:
        start = time.time()
        kwargs = {"model": self.model, "messages": messages}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        resp = await self.client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message

        return LLMResponse(
            content=msg.content or "",
            tool_calls=[{
                "id": tc.id,
                "name": tc.function.name,
                "arguments": json.loads(tc.function.arguments)
            } for tc in (msg.tool_calls or [])],
            tokens_in=resp.usage.prompt_tokens,
            tokens_out=resp.usage.completion_tokens,
            latency_ms=int((time.time() - start) * 1000),
            model=self.model,
        )
```

### 9.3 Anthropic 兼容

```python
# app/core/worker/llm_client.py
from anthropic import AsyncAnthropic

class AnthropicClient(LLMClient):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model

    async def chat(self, messages, tools=None, **kwargs) -> LLMResponse:
        # Anthropic 要求 system 单独提取
        system = ""
        msgs = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                msgs.append(m)

        kwargs = {
            "model": self.model,
            "system": system,
            "messages": msgs,
            "max_tokens": kwargs.get("max_tokens", 4096),
        }
        if tools:
            kwargs["tools"] = tools

        resp = await self.client.messages.create(**kwargs)
        ...
```

### 9.4 多供应商池（负载均衡 + 故障转移）

```python
# app/core/worker/llm_pool.py
class LLMPool:
    def __init__(self, providers: list[dict]):
        """
        providers: [
            {"name": "deepseek", "api_key": "...", "base_url": "...", "model": "deepseek-chat", "weight": 3},
            {"name": "openai",   "api_key": "...", "model": "gpt-5", "weight": 1},
            {"name": "claude",   "api_key": "...", "model": "claude-sonnet-4-6", "weight": 2},
        ]
        """
        self.providers = [self._build_client(p) for p in providers]
        self.weights = [p["weight"] for p in providers]
        self.busy = [False] * len(self.providers)
        self.failed = [0] * len(self.providers)

    def acquire(self) -> LLMClient:
        """加权随机 + 故障检测"""
        available = [i for i, f in enumerate(self.failed) if f < 3]
        if not available:
            # 全部失败，重置
            self.failed = [0] * len(self.providers)
            available = list(range(len(self.providers)))

        # 加权选择
        idx = random.choices(available, weights=[self.weights[i] for i in available])[0]
        self.busy[idx] = True
        return self.providers[idx]

    def release(self, client: LLMClient, success: bool = True):
        idx = self.providers.index(client)
        self.busy[idx] = False
        if not success:
            self.failed[idx] += 1

    def mark_failed(self, client: LLMClient):
        idx = self.providers.index(client)
        self.failed[idx] += 1
```

### 9.5 提示词模拟工具调用（兼容哑模型）

```python
# app/core/worker/llm_client.py - 哑模型兼容
class PromptSimulatedToolClient(LLMClient):
    """对不支持 tool calling 的模型，把工具列表序列化到 prompt 中"""

    def __init__(self, base_client: LLMClient):
        self.base = base_client

    async def chat(self, messages, tools=None, **kwargs):
        if not tools:
            return await self.base.chat(messages, **kwargs)

        # 注入工具说明到 system
        tool_desc = "\n\n可用工具：\n"
        for t in tools:
            schema = t.get("input_schema", {})
            tool_desc += f"- {t['name']}: {t['description']}\n"
            tool_desc += f"  参数: {json.dumps(schema.get('properties', {}), ensure_ascii=False)}\n"
        tool_desc += '\n调用格式：`[TOOL_CALL:name]{"arg": "value"}[/TOOL_CALL]`\n'

        sys_msg = next((m for m in messages if m["role"] == "system"), None)
        if sys_msg:
            sys_msg["content"] += tool_desc

        resp = await self.base.chat(messages, **kwargs)

        # 解析工具调用
        tool_calls = self._parse_tool_calls(resp.content)
        resp.tool_calls = tool_calls
        return resp

    def _parse_tool_calls(self, content: str) -> list[dict]:
        pattern = r'\[TOOL_CALL:(\w+)\](.+?)\[/TOOL_CALL\]'
        matches = re.findall(pattern, content, re.DOTALL)
        return [{
            "id": f"sim-{i}",
            "name": name,
            "arguments": json.loads(args)
        } for i, (name, args) in enumerate(matches)]
```

---

## 10. 通杀 Hunter 与情报沉淀

> **通杀 Hunter（Hunter-Killer）是 Hunter 的核心差异化能力**：当一个漏洞被确认存在后，自动在全网寻找同款漏洞并验证。
> **触发条件**：Reviewer 通过（`pass` 或 `needs_deep`）且 severity ≥ high。
> **安全约束**：所有通杀验证必须经过 `ToolInterceptor`（§14.5），且通过 `ScopeGuard` 三层校验。

### 10.1 通杀整体架构

```
                        ┌──────────────────────────────────┐
                        │   Finding (reviewer_status=passed)│
                        └────────────────┬─────────────────┘
                                         │ on_new_finding hook
                                         ▼
                ┌────────────────────────────────────────┐
                │  ScopeGuard.validate()  ──→  三层校验  │
                │  ├─ 任务授权范围                        │
                │  ├─ 组织白名单                          │
                │  └─ 高风险 → 需用户确认（H-K 看板弹窗）│
                └────────────────┬───────────────────────┘
                                 ▼
        ┌────────────────────────────────────────────────┐
        │ 1. FingerprintExtractor 指纹提取                │
        │    ├─ 漏洞指纹: nuclei template_id / CVE / 组件  │
        │    ├─ PoC 指纹: payload hash + 工具类型          │
        │    └─ 目标指纹: 技术栈 / 端口 / 服务版本          │
        └────────────────┬───────────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────────┐
        │ 2. CandidateSearcher 候选目标搜索                │
        │    ├─ FOFA/Quake/Hunter/ZoomEye (按指纹构造查询)│
        │    ├─ 已扫描目标库中匹配                          │
        │    └─ 去重 + 排除已验证                           │
        └────────────────┬───────────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────────┐
        │ 3. PlanGenerator 验证计划生成                    │
        │    ├─ 每个候选 → VerifyPlan                      │
        │    ├─ payload 可复用性检查                        │
        │    └─ 限速 / 超时设置                            │
        └────────────────┬───────────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────────┐
        │ 4. VerifierPool 并发验证（10 并发）              │
        │    ├─ 每个 verify 调用 ToolInterceptor          │
        │    ├─ 失败重试 + 熔断                            │
        │    └─ 输出截断（≤ 2KB）                          │
        └────────────────┬───────────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────────┐
        │ 5. ResultAggregator 结果聚合                     │
        │    ├─ 验证成功 → 批量新增 Finding                │
        │    ├─ 更新 killsweeps 表（affected_table）        │
        │    └─ 通知前端 H-K 看板                          │
        └────────────────────────────────────────────────┘
```

### 10.2 FingerprintExtractor（指纹提取）

```python
# app/core/hunter_killer/fingerprint.py
from dataclasses import dataclass

@dataclass
class VulnFingerprint:
    """从已验证的 Finding 中提取可搜索的指纹"""

    # 漏洞指纹
    cve_id: Optional[str]                  # CVE-2024-1234
    nuclei_template_id: Optional[str]      # http/cves/2024/CVE-2024-1234
    vuln_type: str                          # sqli / xss / rce / ssrf / ...

    # 组件指纹
    component: Optional[str]               # "log4j", "struts2", "spring"
    component_version: Optional[str]       # "2.17.0"

    # 服务指纹
    tech_stack: list[str]                  # ["nginx", "php", "mysql"]
    port: Optional[int]                    # 80

    # PoC 指纹（用于构造相同 payload）
    poc_hash: Optional[str]                # sha256(poc_template)
    poc_category: Optional[str]            # "time_blind", "boolean_blind", ...

    # 用于搜索引擎的查询模板
    fofa_query: Optional[str]              # title="金融" && region="Beijing"
    quake_query: Optional[str]

    @classmethod
    def from_finding(cls, finding: Finding) -> "VulnFingerprint":
        return VulnFingerprintExtractor(finding).extract()

class VulnFingerprintExtractor:
    def __init__(self, finding: Finding):
        self.finding = finding

    def extract(self) -> VulnFingerprint:
        return VulnFingerprint(
            cve_id=self._extract_cve(),
            nuclei_template_id=self._extract_nuclei_template(),
            vuln_type=self.finding.vuln_type,
            component=self._extract_component(),
            component_version=self._extract_version(),
            tech_stack=self._extract_tech_stack(),
            port=self._extract_port(),
            poc_hash=self._hash_poc(),
            poc_category=self._classify_poc(),
            fofa_query=self._build_fofa_query(),
            quake_query=self._build_quake_query(),
        )

    def _extract_cve(self) -> Optional[str]:
        text = f"{self.finding.template_id} {self.finding.title}"
        match = re.search(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
        return match.group(0).upper() if match else None

    def _extract_component(self) -> Optional[str]:
        for comp in ["log4j", "struts2", "spring", "fastjson", "shiro", "thinkphp"]:
            if comp in self.finding.evidence.lower():
                return comp
        return None

    def _build_fofa_query(self) -> str:
        """构造 FOFA 查询语法"""
        parts = []
        if self.finding.title:
            parts.append(f'title="{self.finding.title[:50]}"')
        if self.component:
            parts.append(f'body="{self.component}"')
        if self.cve_id:
            parts.append(f'banner*="{self.cve_id}"')
        return " && ".join(parts)
```

### 10.3 CandidateSearcher（候选目标搜索）

```python
# app/core/hunter_killer/candidate.py
class CandidateSearcher:
    """根据指纹在多个搜索引擎中搜索候选目标"""

    def __init__(self, engines: list[BaseEngine]):
        self.engines = engines

    async def search(self, fp: VulnFingerprint, max_results: int = 50) -> list[Target]:
        candidates = []
        seen_hosts = set()

        # 1. 在各引擎中搜索
        for engine in self.engines:
            query = self._build_query(engine, fp)
            if not query:
                continue
            results = await engine.search(query, limit=max_results)
            for target in results:
                key = f"{target.host}:{target.port}"
                if key in seen_hosts:
                    continue
                seen_hosts.add(key)
                candidates.append(target)

        # 2. 排除已扫描过的目标
        candidates = await self._exclude_scanned(candidates)

        # 3. 排除已验证通过的（避免重复）
        candidates = await self._exclude_verified(candidates, fp)

        # 4. 应用 ScopeGuard 授权范围过滤
        candidates = await ScopeGuard.filter_candidates(candidates)

        return candidates[:max_results]

    def _build_query(self, engine: BaseEngine, fp: VulnFingerprint) -> str:
        if isinstance(engine, FofaEngine) and fp.fofa_query:
            return fp.fofa_query
        if isinstance(engine, QuakeEngine) and fp.quake_query:
            return fp.quake_query
        if isinstance(engine, HunterEngine):
            parts = []
            if fp.component:
                parts.append(f'web.body="{fp.component}"')
            if fp.cve_id:
                parts.append(f'web.title="{fp.cve_id}"')
            return " && ".join(parts) if parts else ""
        return ""
```

### 10.4 PlanGenerator（验证计划生成）

```python
# app/core/hunter_killer/plan.py
@dataclass
class VerifyPlan:
    target_url: str
    payload: str
    tool: str                        # "http_request" / "sqlmap" / "manual_cmd" ...
    timeout: int = 30
    expected_evidence: str = ""
    poc_category: str = ""           # 与 Finding 的 poc_category 对应

class PlanGenerator:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    async def generate(self, fp: VulnFingerprint,
                       candidate: Target) -> Optional[VerifyPlan]:
        """复用原 Finding 的 PoC 模板，但替换目标。不重新构造 PoC。"""
        original_poc = self.finding.evidence
        template = self._extract_poc_template(original_poc)

        payload = template.replace("{{HOST}}", candidate.host)
        payload = payload.replace("{{PORT}}", str(candidate.port))

        tool = self._select_tool(fp.vuln_type)

        adjust = await self.llm.adjust_poc(
            template=payload,
            target=candidate,
            vuln_type=fp.vuln_type,
        )
        if adjust.rejected:
            return None
        if adjust.modified:
            payload = adjust.modified

        return VerifyPlan(
            target_url=candidate.url,
            payload=payload,
            tool=tool,
            timeout=30,
            poc_category=fp.poc_category,
        )

    def _select_tool(self, vuln_type: str) -> str:
        return {
            "sqli": "sqlmap",
            "xss": "manual_xss",
            "rce": "manual_cmd",
            "ssrf": "http_request",
            "lfi": "file_read",
        }.get(vuln_type, "http_request")
```

### 10.5 ScopeGuard（授权范围校验 — 必须三层校验）

```python
# app/core/hunter_killer/scope.py
class ScopeGuard:
    """通杀 Hunter 的范围校验 — 三层必须全部通过"""

    @classmethod
    async def validate(cls, plan: VerifyPlan, source_finding: Finding) -> bool:
        results = []
        results.append(await cls._check_task_authorization(plan))
        results.append(await cls._check_org_whitelist(plan))
        if cls._is_high_risk(source_finding):
            results.append(await cls._require_user_confirm(plan))
        return all(results)

    @staticmethod
    async def _check_task_authorization(plan: VerifyPlan) -> bool:
        task = await get_task_by_finding(plan.source_finding_id)
        authorized_hosts = task.authorized_hosts
        return plan.target_host in authorized_hosts

    @staticmethod
    async def _check_org_whitelist(plan: VerifyPlan) -> bool:
        org = await get_current_org()
        return plan.target_host in org.whitelist_hosts

    @staticmethod
    def _is_high_risk(finding: Finding) -> bool:
        return finding.severity in {"critical", "high"}

    @staticmethod
    async def _require_user_confirm(plan: VerifyPlan) -> bool:
        return await wait_for_user_confirm(plan, timeout=300)
```

### 10.6 VerifierPool（并发验证 — 必须调用 ToolInterceptor）

```python
# app/core/hunter_killer/verifier.py
class VerifierPool:
    """并发执行 VerifyPlan，全部经过 ToolInterceptor"""

    def __init__(self, max_concurrent: int = 10, rate_limit_rps: float = 2.0):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limiter = AsyncRateLimiter(rate_limit_rps)
        self.interceptor = ToolInterceptor()  # ★ 必须使用 v3 拦截器

    async def verify_all(self, plans: list[VerifyPlan]) -> list[VerificationResult]:
        tasks = [self._verify_one(p) for p in plans]
        return await asyncio.gather(*tasks)

    async def _verify_one(self, plan: VerifyPlan) -> VerificationResult:
        async with self.semaphore:
            await self.rate_limiter.acquire()

            # ★ 必须先经过 ToolInterceptor
            decision = await self.interceptor.check(
                tool_name=plan.tool,
                args={"url": plan.target_url, "payload": plan.payload},
                worker_run_id=plan.source_finding.worker_run_id,
            )
            if not decision.allowed:
                return VerificationResult(
                    plan=plan,
                    success=False,
                    error="blocked_by_safety",
                    evidence=decision.reason,
                )

            try:
                result = await self._execute(plan)
                if decision.class_ == OperationClass.READ_LIMITED:
                    limit = decision.modifications.get("max_bytes", 2048)
                    result.evidence = truncate(result.evidence, limit)
                return VerificationResult(plan=plan, success=True, evidence=result.evidence)
            except Exception as e:
                return VerificationResult(plan=plan, success=False, error=str(e))

    async def _execute(self, plan: VerifyPlan):
        if plan.tool == "sqlmap":
            return await self.tools.sqlmap.run(payload=plan.payload, url=plan.target_url)
        if plan.tool == "manual_cmd":
            return await self.tools.manual_cmd.run(command=plan.payload)
        if plan.tool == "manual_xss":
            return await self.tools.manual_xss.run(payload=plan.payload)
        if plan.tool == "http_request":
            return await self.tools.http_request.run(url=plan.target_url, body=plan.payload)
```

### 10.7 ResultAggregator（结果聚合）

```python
# app/core/hunter_killer/aggregator.py
class ResultAggregator:
    """把验证成功的候选批量新增 Finding"""

    async def aggregate(self, results: list[VerificationResult],
                       source_finding: Finding) -> HunterKillerRun:
        run = HunterKillerRun(
            source_finding_id=source_finding.id,
            started_at=datetime.utcnow(),
            candidates_total=len(results),
        )

        verified_count = 0
        for r in results:
            if r.success and r.vulnerable:
                new_finding = Finding(
                    target_url=r.plan.target_url,
                    vuln_type=source_finding.vuln_type,
                    severity=source_finding.severity,
                    template_id=source_finding.template_id,
                    evidence=r.evidence,
                    poc_hash=source_finding.poc_hash,
                    source="hunter_killer",
                    source_finding_id=source_finding.id,
                    reviewer_status="auto_verified",
                )
                await db.add(new_finding)
                verified_count += 1
            elif not r.success and r.error == "blocked_by_safety":
                run.blocked_count += 1

        run.verified_count = verified_count
        run.finished_at = datetime.utcnow()
        await db.add(run)
        await db.commit()

        return run
```

### 10.8 主调度循环

```python
# app/core/hunter_killer/dispatcher.py
class HunterKillerDispatcher:
    """监听 Finding → 触发通杀"""

    async def on_new_finding(self, finding: Finding):
        # 触发条件：Reviewer 通过且 severity >= high
        if finding.reviewer_status != "passed":
            return
        if finding.severity not in {"critical", "high"}:
            return

        fp = VulnFingerprint.from_finding(finding)

        # 1. 候选搜索
        searcher = CandidateSearcher(self.engines)
        candidates = await searcher.search(fp, max_results=50)
        if not candidates:
            return

        # 2. 计划生成 + ScopeGuard 校验
        generator = PlanGenerator(self.llm)
        plans = []
        for c in candidates:
            plan = await generator.generate(fp, c)
            if plan and await ScopeGuard.validate(plan, finding):
                plans.append(plan)

        # 3. 并发验证
        pool = VerifierPool(max_concurrent=10, rate_limit_rps=2)
        results = await pool.verify_all(plans)

        # 4. 聚合
        aggregator = ResultAggregator()
        run = await aggregator.aggregate(results, finding)

        # 5. 通知前端 H-K 看板
        await self.notify_frontend(run)
```

### 10.9 通杀数据存储（基线已实现）

> **MVP 基线**：当前基线已用 **`killsweeps` 表**实现通杀存储（§4.2⑤）：`product_key` 产品指纹去重（同任务同款只一条）、`affected_table` 影响明细、`verified` 验证标记，UUID 主键。**无需新增表**。
>
> **远期扩展**（如新增"通杀打点流水"等）必须遵循 §4 兼容性红线：**只允许新增表 / 新增列（带 DEFAULT）**，严禁修改既有 `killsweeps` 结构。示例（仅作示意，落地前需评审）：

```sql
-- 远期示例：通杀打点流水表（新增表，不碰 killsweeps）
CREATE TABLE killsweep_hits (
    id TEXT(32) PRIMARY KEY,             -- UUID
    killsweep_id TEXT(32) NOT NULL,      -- → killsweeps.id
    target_id TEXT(32) NOT NULL,         -- → targets.id
    url TEXT NOT NULL,
    title TEXT,
    status TEXT DEFAULT 'pending',       -- pending/verified/failed
    evidence TEXT,
    created_at DATETIME
);
CREATE INDEX ix_kh_killsweep ON killsweep_hits(killsweep_id);
```

### 10.10 情报沉淀库（Intel Store）

```python
# app/core/intel/store.py
class IntelStore:
    """验证过的情报入库，供后续 Worker 复用"""

    async def record(self, kind: str, value: str, tags: dict,
                     source_finding_id: int):
        """类型: credential / endpoint / fingerprint / payload"""
        await db.add(IntelRecord(
            kind=kind, value=value, tags=json.dumps(tags),
            source_finding_id=source_finding_id,
            created_at=datetime.utcnow(),
        ))
        await db.commit()

    async def search(self, kind: str, query: str) -> list[IntelRecord]:
        return await db.execute(
            select(IntelRecord).where(
                IntelRecord.kind == kind,
                IntelRecord.value.contains(query),
            )
        ).all()

    async def get_endpoints_for_target(self, target: Target) -> list[str]:
        """已知端点直接喂给 Agent，跳过目录扫描"""
        return await db.execute(
            select(IntelRecord.value).where(
                IntelRecord.kind == "endpoint",
                IntelRecord.value.contains(target.host),
            )
        ).all()
```

### 10.11 通杀性能指标

| 指标 | 目标值 | 监控 |
|---|---|---|
| 候选搜索延迟 | < 10s | HK 看板 |
| 单目标验证延迟 | < 30s | HK 看板 |
| 通杀成功率 | ≥ 30%（验证成功 / 候选总数） | 统计 |
| 安全拦截率 | < 10% | safety_denied_total{tool="hk"} |
| 批量 Finding 增量 | 单次通杀 5-50 条 | hunter_killer_verified_total |

### 10.12 通杀典型场景

#### 场景 A：CVE 漏洞扩散（Struts2 S2-061）

```
1. Worker A 扫描出某 Struts2 应用存在 S2-061
2. Reviewer 通过（high）
3. FingerprintExtractor 提取: cve=CVE-2020-17530, component=struts2
4. CandidateSearcher 在 FOFA 搜: banner*="struts2"
5. 找到 50 个候选（去重、已扫描排除后剩 30）
6. PlanGenerator 复用原 PoC，替换目标
7. VerifierPool 并发 10 个验证
8. ResultAggregator 新增 18 条 Finding
```

#### 场景 B：SQLi 通用 Payload

```
1. Worker 发现某 CMS 存在时间盲注
2. Reviewer 通过（high）
3. 指纹: vuln_type=sqli, poc_category=time_blind, payload="1' AND SLEEP(5)-- -"
4. CandidateSearcher 搜该 CMS 的目标
5. 候选 50 个 → PlanGenerator 替换 host 部分
6. 验证 → 35 个同样存在时间盲注 → 批量入库
```

### 10.13 通杀安全约束（再次强调）

通杀 Hunter 是**最容易失控**的功能，必须严守：

- ✅ 必须经过 `ToolInterceptor`（§14.5）
- ✅ 必须经过 `ScopeGuard` 三层校验（§10.5）
- ✅ 必须限制候选数量（默认 ≤ 50）
- ✅ 必须限速（默认 2 RPS）
- ✅ 必须记录审计（基线：task_events；通杀结论落 killsweeps.notes）
- ✅ 高风险必须用户确认
- ❌ 禁止自动执行 payload 修复/变形

---

## 11. 报告生成与交付

### 11.1 多格式导出

```python
# app/reports/generator.py
class ReportGenerator:
    def __init__(self, finding: Finding, target: Target, task: Task):
        self.finding = finding
        self.target = target
        self.task = task

    def render_markdown(self) -> str:
        return MARKDOWN_TEMPLATE.render(
            finding=self.finding, target=self.target, task=self.task,
            now=datetime.now().isoformat()
        )

    def render_html(self) -> str:
        return HTML_TEMPLATE.render(...)

    def render_pdf(self) -> bytes:
        # 使用 weasyprint 或 playwright 渲染 HTML
        from weasyprint import HTML
        return HTML(string=self.render_html()).write_pdf()

    def render_json(self) -> dict:
        return self.finding.to_dict() | {
            "target": self.target.to_dict(),
            "task_id": self.task.id
        }
```

### 11.2 报告模板（Markdown 示例）

```markdown
# {{ finding.title }}

> **漏洞类型**: {{ finding.vuln_type }}
> **危害等级**: {{ finding.severity }}
> **提交时间**: {{ now }}

## 1. 漏洞概述

{{ finding.description }}

## 2. 危害影响

{{ finding.impact }}

## 3. 复现步骤

{{ finding.reproduction }}

### 3.1 请求包

```http
{{ finding.evidence }}
```

### 3.2 Payload

```
{{ finding.payload }}
```

## 4. 目标信息

- **URL**: {{ target.url }}
- **IP**: {{ target.ip }}:{{ target.port }}
- **归属**: {{ target.org }}
- **Server**: {{ target.server }}

## 5. 修复建议

{{ finding.remediation }}

---

<sub>本报告由 Hunter v{{ version }} 生成</sub>
```

---

## 12. RBAC 与审计日志

### 12.1 角色与权限矩阵

| 角色 | 创建任务 | 触发扫描 | 编辑 Finding | 通过/打回 | 用户管理 | 查看审计 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **operator** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **reader** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **observer** | ❌ | ❌ | ❌ | ❌ | ❌ | 仅看板 |

### 12.2 令牌系统

```python
# app/security/tokens.py
import secrets

class TokenManager:
    @staticmethod
    def generate(role: str, name: str, expires_days: int = None) -> Token:
        raw = secrets.token_urlsafe(48)  # 64 字符
        return Token(
            token=hashlib.sha256(raw.encode()).hexdigest(),
            name=name,
            role=role,
            expires_at=datetime.now() + timedelta(days=expires_days)
                  if expires_days else None
        )

    @staticmethod
    async def verify(token: str) -> tuple[str, str]:
        """返回 (role, username)"""
        hashed = hashlib.sha256(token.encode()).hexdigest()
        # 查 DB
        ...
```

### 12.3 审计中间件

```python
# app/audit/logger.py
from fastapi import Request

class AuditMiddleware:
    async def __call__(self, request: Request, call_next):
        # 不审计的路径
        if request.url.path in {"/health", "/docs", "/openapi.json"}:
            return await call_next(request)

        actor, role = await self._extract_actor(request)
        start = time.time()
        response = await call_next(request)
        elapsed = int((time.time() - start) * 1000)

        await self._log(
            actor=actor or "anonymous",
            role=role or "guest",
            action=f"{request.method} {request.url.path}",
            resource=request.url.path,
            method=request.method,
            payload_hash=hashlib.sha256(await request.body()).hexdigest()
                       if request.method in {"POST", "PUT", "PATCH"} else None,
            result="success" if response.status_code < 400 else "denied",
            ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
            duration_ms=elapsed,
        )
        return response
```

### 12.4 LLM 调用审计

```python
# app/audit/llm_audit.py
# 【远期设计示意】基线暂无 LLM trace 表；落地时按 §4 红线新增表（如 llm_traces），
# 不得依赖 worker_run_id（基线无该表），用 worker_id / task_id 关联。
async def audit_llm_call(worker_run_id: int, request: dict, response: LLMResponse):
    """所有 LLM 调用落 trace 表，可回放"""
    async with async_session() as s:
        trace = LLMTrace(
            worker_run_id=worker_run_id,
            round=request.get("round", 0),
            role="assistant",
            content=response.content[:50000],  # 截断防膨胀
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            latency_ms=response.latency_ms,
        )
        s.add(trace)
        await s.commit()
```

---

## 13. Web 控制台 (Vue 3)

### 13.1 页面与路由

```typescript
// frontend/src/router/index.ts
const routes = [
  { path: "/login", component: () => import("@/views/Login.vue") },
  {
    path: "/",
    component: () => import("@/layouts/MainLayout.vue"),
    meta: { requiresAuth: true },
    children: [
      { path: "", redirect: "/dashboard" },
      { path: "dashboard", component: () => import("@/views/Dashboard.vue") },
      { path: "tasks", component: () => import("@/views/Tasks.vue") },
      { path: "tasks/create", component: () => import("@/views/TaskCreate.vue") },
      { path: "tasks/:id", component: () => import("@/views/TaskDetail.vue") },
      { path: "findings", component: () => import("@/views/Findings.vue") },
      { path: "findings/:id", component: () => import("@/views/FindingDetail.vue") },
      { path: "settings", component: () => import("@/views/Settings.vue"),
        meta: { roles: ["admin"] } },
      { path: "audit", component: () => import("@/views/Audit.vue"),
        meta: { roles: ["admin"] } },
      { path: "stats", component: () => import("@/views/Stats.vue") },
    ],
  },
]
```

### 13.2 看板页面（实时事件流）

```vue
<!-- frontend/src/views/Dashboard.vue -->
<template>
  <div class="dashboard">
    <!-- 概览卡片 -->
    <el-row :gutter="16">
      <el-col :span="6"><StatCard label="活跃 Worker" :value="stats.activeWorkers" /></el-col>
      <el-col :span="6"><StatCard label="待审 Finding" :value="stats.pendingFindings" /></el-col>
      <el-col :span="6"><StatCard label="今日挖洞" :value="stats.todayFindings" /></el-col>
      <el-col :span="6"><StatCard label="LLM 成本(今日)" :value="stats.todayCost" /></el-col>
    </el-row>

    <!-- Worker 实时状态 -->
    <el-card title="Worker 实时状态">
      <WorkerGrid :workers="workers" />
    </el-card>

    <!-- 事件流 -->
    <el-card title="事件流">
      <EventStream :events="events" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from "vue"
import { useDashboardStore } from "@/stores/dashboard"

const statsStore = useDashboardStore()
const workers = ref([])
const events = ref([])
let ws: WebSocket

onMounted(() => {
  // WebSocket 实时推送
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/v1/ws`)
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data)
    if (msg.type === "worker_update") workers.value = msg.payload
    if (msg.type === "event") events.value.unshift(msg.payload)
  }
})

onUnmounted(() => ws?.close())
</script>
```

### 13.3 任务创建向导

```vue
<!-- frontend/src/views/TaskCreate.vue -->
<template>
  <el-steps :active="step" finish-status="success">
    <el-step title="基础信息" />
    <el-step title="目标来源" />
    <el-step title="漏洞类型" />
    <el-step title="高级配置" />
    <el-step title="确认" />
  </el-steps>

  <el-form v-show="step === 0">
    <el-form-item label="任务名称">
      <el-input v-model="form.name" />
    </el-form-item>
    <el-form-item label="任务模式">
      <el-radio-group v-model="form.mode">
        <el-radio-button label="edu">教育行业</el-radio-button>
        <el-radio-button label="enterprise">企业SRC</el-radio-button>
      </el-radio-group>
    </el-form-item>
  </el-form>

  <el-form v-show="step === 1">
    <el-form-item label="目标来源">
      <el-radio-group v-model="form.source">
        <el-radio-button label="fofa">FOFA 自动搜</el-radio-button>
        <el-radio-button label="manual">手动清单</el-radio-button>
        <el-radio-button label="both">两者</el-radio-button>
      </el-radio-group>
    </el-form-item>
    <el-form-item label="搜集方式">
      <el-radio-group v-model="form.collectMethod">
        <el-radio-button label="auto">自动判断</el-radio-button>
        <el-radio-button label="fofa_syntax">FOFA 语法</el-radio-button>
        <el-radio-button label="nl_intent">自然语言意图</el-radio-button>
      </el-radio-group>
    </el-form-item>
    <el-form-item v-if="form.source !== 'manual'" label="FOFA 语法 / 意图">
      <el-input v-model="form.query" type="textarea" :rows="4"
                placeholder="FOFA 语法 或 自然语言描述" />
    </el-form-item>
    <el-form-item v-if="form.source !== 'fofa'" label="手动目标清单">
      <el-upload :auto-upload="false" :on-change="handleFileUpload">
        <el-button>选择文件</el-button>
      </el-upload>
      <el-input v-model="form.manualTargets" type="textarea" :rows="6" />
    </el-form-item>
  </el-form>

  <!-- ... -->
</template>
```

### 13.4 Finding 复审页

```vue
<!-- frontend/src/views/Findings.vue -->
<template>
  <el-table :data="findings" stripe>
    <el-table-column prop="id" label="ID" width="60" />
    <el-table-column prop="severity" label="等级">
      <template #default="{ row }">
        <SeverityTag :level="row.severity" />
      </template>
    </el-table-column>
    <el-table-column prop="vulnType" label="类型" />
    <el-table-column prop="title" label="标题" show-overflow-tooltip />
    <el-table-column prop="target.url" label="目标" />
    <el-table-column label="Reviewer">
      <template #default="{ row }">
        <el-tag v-if="row.reviewerStatus === 'passed'" type="success">通过</el-tag>
        <el-tag v-else-if="row.reviewerStatus === 'needs_deep'" type="warning">回炉</el-tag>
        <el-tag v-else type="danger">拒绝</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="人工">
      <template #default="{ row }">
        <el-button-group>
          <el-button @click="approve(row)" type="success" size="small">通过</el-button>
          <el-button @click="reject(row)" type="danger" size="small">打回</el-button>
          <el-button @click="escalate(row)" type="warning" size="small">调级</el-button>
        </el-button-group>
      </template>
    </el-table-column>
  </el-table>
</template>
```

---

## 14. 安全护栏与熔断（v3 无害化 PoC 模型）

> **v3 是当前唯一权威的安全模型**。前序版本（黑名单硬拦截、InputFilter）已被弃用。
> **核心理念**：每个漏洞类型都有"标准无害化验证动作"（白名单），LLM 在白名单范围内自主选择验证方式，系统做边界守卫。危险操作由系统硬拦截。

### 14.1 v3 安全模型总览

```
                    ┌─────────────────────────────────┐
                    │  WorkerAgent (ReAct, 80 轮)      │
                    │  prompt 注入 SAFETY §5.1 决策框架│
                    └────────────┬────────────────────┘
                                 │ 每次 tool call
                                 ▼
                    ┌─────────────────────────────────┐
                    │  ToolInterceptor (SAFETY §6)     │
                    │  ├─ RCEWhitelist    (白名单)     │
                    │  ├─ SSRFWhitelist   (公网域名)   │
                    │  ├─ XSSWhitelist    (alert PoC)  │
                    │  ├─ SQLGuard        (LIMIT 3)    │
                    │  └─ FileReadGuard   (白名单文件) │
                    └────────────┬────────────────────┘
                                 │ allowed?
                          ┌──────┴──────┐
                          │             │
                          ▼             ▼
                    ┌─────────┐  ┌──────────────────┐
                    │ 执行工具 │  │ 拒绝 + 审计记录  │
                    └────┬────┘  └──────────────────┘
                         │
                         ▼
                  ┌────────────────┐
                  │ Hunter-Killer  │
                  │ VerifierPool   │
                  │ (调用同一拦截器)│
                  └────────────────┘
```

### 14.2 RCE 无害化命令白名单

```python
# app/security/safety/rce_whitelist.py
class RCEWhitelist:
    """RCE 无害化命令白名单"""

    # 允许的只读验证命令
    SAFE_COMMANDS = {
        # 身份
        "whoami", "id", "hostname",
        "uname", "uname -a", "uname -r",
        # 网络
        "ifconfig", "ip addr", "ip route",
        "cat /etc/hosts", "cat /etc/resolv.conf",
        # 系统信息
        "cat /etc/passwd", "cat /etc/issue", "cat /etc/os-release",
        "cat /proc/version", "lsb_release -a", "arch",
        # 进程
        "ps aux", "ps -ef", "ps aux | head -20",
        # 环境变量
        "env | head -20", "printenv",
        # 时间盲注
        "sleep 3", "sleep 5", "sleep 10",
        # DNS 出网
        "nslookup www.baidu.com", "nslookup www.example.com",
        "dig www.baidu.com", "host www.baidu.com",
    }

    # 黑名单（任何情况都禁止）
    FORBIDDEN_PATTERNS = [
        # 文件删除
        r'\brm\s+', r'\bmv\s+/', r'\btruncate\b',
        # 系统破坏
        r'\bshutdown\b', r'\breboot\b', r'\bhalt\b',
        r'\bmkfs\b', r'\bdd\s+if=',
        # 反弹 shell
        r'\bbash\s+-i\s+>&\s*/dev/tcp/',
        r'\bnc\s+-[el]+\b', r'\bncat\s+-[el]+\b',
        r'\bpython\s+.*socket.*connect',
        # 持久化
        r'>\s*/etc/cron', r'>>\s*/root/\.ssh/authorized_keys',
        # 远程下载执行
        r'\bwget\s+.*\|\s*(bash|sh)',
        r'\bcurl\s+.*\|\s*(bash|sh)',
        # 用户管理
        r'\buseradd\b', r'\buserdel\b', r'\bpasswd\s+\w+',
    ]

    MAX_OUTPUT_BYTES = 1024
    MAX_SLEEP_TIME = 30

    def is_safe(self, command: str) -> tuple[bool, str]:
        cmd = command.strip().lower()
        for pattern in self.FORBIDDEN_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return False, f"禁止命令: {pattern}"
        if cmd in self.SAFE_COMMANDS:
            return True, "白名单命令"
        return False, "不在白名单（仅允许只读验证命令）"
```

### 14.3 SSRF 公网白名单

```python
# app/security/safety/ssrf_whitelist.py
class SSRFWhitelist:
    """SSRF 无害化验证：仅允许指向公网已知域名"""

    PUBLIC_DOMAINS = {
        "www.baidu.com", "www.qq.com", "www.163.com",
        "www.example.com", "www.google.com", "www.bing.com",
        "dns.alidns.com", "one.one.one.one", "8.8.8.8",
    }

    PUBLIC_DNS_IPS = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1",
        "114.114.114.114", "223.5.5.5", "180.76.76.76",
    }

    PRIVATE_RANGES = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16",  # 云元数据
    ]

    def is_safe_target(self, url: str) -> tuple[bool, str]:
        parsed = urlparse(url)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"}:
            return False, f"不支持的协议: {parsed.scheme}"
        if host in self.PUBLIC_DOMAINS:
            return True, "公网无害域名"
        try:
            ip = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(ip)
            for range_ in self.PRIVATE_RANGES:
                if ip_obj in ipaddress.ip_network(range_):
                    return False, f"私有 IP 禁止: {ip}"
            if ip in self.PUBLIC_DNS_IPS:
                return True, f"公网 DNS IP: {ip}"
        except (socket.gaierror, ValueError):
            return False, f"DNS 解析失败: {host}"
        return False, "不在公网白名单"
```

### 14.4 XSS / SQLi / 文件守卫

```python
# app/security/safety/xss_whitelist.py
class XSSWhitelist:
    SAFE_PAYLOADS = {
        "<script>alert(1)</script>",
        "<script>confirm(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    }
    FORBIDDEN_PAYLOADS = [
        r'document\.cookie',                # 窃取 cookie
        r'addEventListener\s*\(\s*["\']key', # 键盘记录
        r'XMLHttpRequest', r'fetch\s*\(',
        r'window\.location\s*=',            # 钓鱼重定向
        r'navigator\.mediaDevices',          # 摄像头/麦克风
        r'coinhive|cryptonight|miner',       # 挖矿
    ]

# app/security/safety/sql_guard.py
class SQLGuard:
    UNIVERSAL_DENY = [
        r'\bdrop\s+database\b', r'\bshutdown\b', r'\bgrant\s+',
        r'\bload_file\s*\(',                 # 任意文件读取
        r'into\s+(out|dump)file\b',          # 任意文件写入
        r'\bxp_cmdshell\b',
    ]
    TARGET_DENY = [                          # TARGET 禁止写
        r'\binsert\s+', r'\bupdate\s+\w+\s+set\b',
        r'\bdelete\s+', r'\bdrop\s+(table|database)\b',
        r'\balter\s+table\b', r'\btruncate\b',
    ]
    MAX_ROWS = 3                             # 最多取 3 条
    MAX_BYTES = 2048                         # 单条响应 ≤ 2KB

    def audit(self, payload: str, context) -> ActionDecision:
        p = payload.lower()
        for pat in self.UNIVERSAL_DENY:
            if re.search(pat, p, re.IGNORECASE):
                return ActionDecision(False, OperationClass.DESTRUCTIVE, f"禁止 SQL: {pat}")
        if context.is_target_resource:
            for pat in self.TARGET_DENY:
                if re.search(pat, p, re.IGNORECASE):
                    return ActionDecision(False, OperationClass.DESTRUCTIVE, f"禁止对目标: {pat}")
            if "select" in p and "limit" not in p:
                payload = self._inject_limit(payload, self.MAX_ROWS)
            return ActionDecision(True, OperationClass.READ_LIMITED, "目标只读（≤ 3 条）")

# app/security/safety/file_read_guard.py
class FileReadGuard:
    TARGET_READ_WHITELIST = {
        "/etc/passwd", "/etc/hosts", "/etc/issue",
        "/etc/os-release", "/proc/version",
    }
    FORBIDDEN_PATTERNS = [
        r'/etc/shadow', r'/root/\.ssh/', r'.*\.key$', r'.*\.pem$',
    ]
    SELF_PATH_PATTERNS = [
        r'^/tmp/hunter/.*', r'^/var/tmp/hunter/.*', r'^\.\/uploads/.*',
    ]
    MAX_BYTES = 2048

    def audit(self, path: str, operation: str, context) -> ActionDecision:
        # 禁止
        for pat in self.FORBIDDEN_PATTERNS:
            if re.search(pat, path):
                return ActionDecision(False, OperationClass.DESTRUCTIVE, f"禁止: {pat}")
        # SELF（24h 内可删改）
        if any(re.search(p, path) for p in self.SELF_PATH_PATTERNS):
            return ActionDecision(True, OperationClass.WRITE, "SELF 资源")
        # TARGET 读
        if context.is_target_resource and operation == "read":
            if path in self.TARGET_READ_WHITELIST:
                return ActionDecision(True, OperationClass.READ_LIMITED, f"TARGET 白名单: {path}")
            return ActionDecision(False, OperationClass.DESTRUCTIVE, f"不在 TARGET 白名单")
        return ActionDecision(False, OperationClass.DESTRUCTIVE, "禁止")
```

### 14.5 ToolInterceptor（统一拦截器）

```python
# app/security/safety/tool_interceptor.py
class OperationClass(str, Enum):
    READ_SAFE = "read_safe"
    READ_LIMITED = "read_limited"
    WRITE = "write"
    DESTRUCTIVE = "destructive"

@dataclass
class ActionDecision:
    allowed: bool
    class_: OperationClass
    reason: str
    modifications: dict = None

class ToolInterceptor:
    """所有工具调用必须经过此拦截器"""

    def __init__(self):
        self.rce = RCEWhitelist()
        self.ssrf = SSRFWhitelist()
        self.xss = XSSWhitelist()
        self.sql = SQLGuard()
        self.file = FileReadGuard()

    async def check(self, tool_name: str, args: dict,
                   worker_run_id: int) -> ActionDecision:
        # RCE
        if tool_name in {"manual_cmd", "rce_poc", "command_exec"}:
            allowed, reason = self.rce.is_safe(args.get("command", ""))
            return ActionDecision(
                allowed, OperationClass.READ_LIMITED if allowed else OperationClass.DESTRUCTIVE,
                reason, {"max_output": 1024},
            )
        # SSRF
        if tool_name in {"http_request", "curl", "ssrf_test"}:
            if self._is_ssrf_context(args):
                allowed, reason = self.ssrf.is_safe_target(args.get("url", ""))
                if not allowed:
                    return ActionDecision(False, OperationClass.DESTRUCTIVE, reason)
        # XSS
        if tool_name in {"manual_xss", "xss_poc"}:
            allowed, reason = self.xss.is_safe_payload(args.get("payload", ""))
            return ActionDecision(allowed, OperationClass.READ_SAFE, reason)
        # SQL
        if tool_name in {"sqlmap", "manual_sqli"}:
            return self.sql.audit(args.get("payload", ""), self._ctx(args))
        # 文件
        if tool_name in {"file_read", "lfi", "file_write", "file_delete"}:
            return self.file.audit(args.get("path", ""), tool_name.split("_")[0], self._ctx(args))
        return ActionDecision(True, OperationClass.READ_SAFE, "未知工具")


async def execute_tool_safely(tool, args, worker_run_id):
    """Worker 调用入口：所有工具调用都必须经过此函数"""
    interceptor = ToolInterceptor()
    decision = await interceptor.check(tool.name, args, worker_run_id)

    if not decision.allowed:
        await audit_dangerous_attempt(worker_run_id, tool.name, args, decision.reason)
        raise ToolForbiddenError(decision.reason)

    # 应用自动修正（如自动注入 LIMIT N）
    args = await interceptor.apply_modifications(decision, args)

    result = await tool.execute(args)

    # 截断输出（READ_LIMITED）
    if decision.class_ == OperationClass.READ_LIMITED:
        limit = decision.modifications.get("max_bytes", 2048)
        result.output = truncate(result.output, limit)

    return result
```

**接入点**（必须全部经过 `execute_tool_safely`）：
- Worker ReAct 循环主入口（`app/core/worker/repl.py`）
- Hunter-Killer VerifierPool（§10.6）
- 任何手工触发的脚本

### 14.6 LLM 自主决策 Prompt

```python
# app/core/worker/agent_safety_prompt.py
AGENT_SAFETY_SYSTEM_PROMPT = """你是安全研究员 Agent，每个挖洞动作都必须遵守"无害化 PoC"原则。

# 核心原则
每个漏洞类型都有标准的无害化验证动作，证明漏洞存在，但不造成真实危害。

# 各漏洞类型的推荐验证方式

## RCE（命令执行）
- 允许命令：whoami, id, hostname, uname -a, cat /etc/passwd, sleep N, nslookup www.baidu.com
- 禁止：反弹 shell、写文件、删文件、远程下载执行

## SSRF（服务端请求伪造）
- 允许目标：http://www.baidu.com, http://www.example.com, http://8.8.8.8
- 禁止：内网 IP（10.x、172.16.x、192.168.x、127.x）、云元数据（169.254.169.254）

## XSS（跨站脚本）
- 允许 payload：<script>alert(1)</script>, <img src=x onerror=alert(1)>, <svg onload=alert(1)>
- 禁止：document.cookie、fetch()、XMLHttpRequest、键盘记录

## SQLi（SQL 注入）
- 允许：SELECT ... LIMIT 3（系统自动注入 LIMIT）
- 禁止：INSERT/UPDATE/DELETE/DROP/LOAD_FILE/INTO OUTFILE

## LFI（本地文件包含）
- 允许：/etc/passwd, /etc/hosts, /proc/version
- 禁止：/etc/shadow, /root/.ssh/*, *.key

# 自主决策
1. 首选无害化 PoC：从上述白名单选择验证动作
2. 需要更深验证：如果白名单不够，可向用户申请扩展
3. 危险动作：反弹 shell、写 shell、删数据等 → 永远不做

# 工具调用格式
每次调用工具时，必须在 thought 中说明：
- 这是什么类型的漏洞
- 选择的验证方式是什么
- 为什么这是无害化的
- 证据如何收集
"""
```

### 14.7 SELF vs TARGET 资源所有权

```python
# app/security/safety/resource_context.py
class ResourceContext:
    """区分 SELF 资源（自上传）和 TARGET 资源（授权目标）"""

    def __init__(self, is_self: bool, is_target: bool, target_host: str):
        self.is_self_resource = is_self
        self.is_target_resource = is_target
        self.target_host = target_host

    @classmethod
    def from_target(cls, url: str):
        parsed = urlparse(url)
        host = parsed.hostname
        is_self = any(host.startswith(p) for p in ["self.", "hunter-self."])
        is_target = not is_self
        return cls(is_self, is_target, host)
```

**规则**：
- **SELF 资源**（`/tmp/hunter/*`、`./uploads/*`）：24h 内可读 / 写 / 删除（这就是"自己的文件可以删"的来源）
- **TARGET 资源**：仅 GET / HEAD 读，严格按各类型白名单；禁止任何写 / 删

### 14.8 紧急熔断（L0 隔离下最高安全开关）

```python
# app/core/emergency.py
class EmergencyStop:
    """可由用户随时激活，不可被白名单绕过"""

    _active = False
    _lock = asyncio.Lock()

    @classmethod
    async def activate(cls, reason: str, user: str):
        async with cls._lock:
            cls._active = True
            await audit_critical("emergency_stop_activated", reason=reason, user=user)

    @classmethod
    def is_active(cls) -> bool:
        return cls._active

    @classmethod
    async def deactivate(cls, user: str):
        async with cls._lock:
            cls._active = False
            await audit_critical("emergency_stop_deactivated", user=user)

# 每个 Agent 循环的每轮 ReAct 都检查
async def agent_loop(self):
    for round_idx in range(self.max_rounds):
        # 紧急熔断检查 — 不可被白名单绕过
        if EmergencyStop.is_active():
            return {"status": "stopped", "reason": "emergency_stop"}
        # ... 正常 ReAct 逻辑
```

**触发方式**：
- Web 控制台：Dashboard 顶部红色按钮
- API（MVP 基线）：`POST /api/tasks/{task_id}/stop`（停任务）、`POST /api/tasks/{task_id}/pause`（暂停，均可恢复），见 §13
- 远期增强：全局紧急熔断 API `POST /api/v1/emergency/activate`（§18），命令行 `hunter-cli emergency-stop` 为远期待建

### 14.9 连续失败熔断（Worker 层）

```python
# app/core/breaker.py
class CircuitBreaker:
    """同一目标连续失败 N 次 → 自动熔断，跳过"""

    def __init__(self, threshold: int = 5, cooldown: int = 300):
        self.failures: dict[str, int] = defaultdict(int)
        self.last_failure: dict[str, float] = {}
        self.threshold = threshold
        self.cooldown = cooldown

    async def is_open(self, key: str) -> bool:
        if self.failures[key] >= self.threshold:
            if time.time() - self.last_failure[key] < self.cooldown:
                return True
            else:
                self.failures[key] = 0
        return False

    def record_failure(self, key: str):
        self.failures[key] += 1
        self.last_failure[key] = time.time()
```

### 14.10 已弃用的方案

| 弃用方案 | 原位置 | 替代方案 |
|---|---|---|
| 黑名单硬拦截 `BLACKLIST_KEYWORDS` | 旧 §6.1 | §14.5 ToolInterceptor 白名单 |
| `InputFilter` 报告脱敏 | 旧 §14.3 | 不脱敏（证据需要完整） |
| `emergency_stop` 行级 DB 存储 | 旧 §14.1 | 进程内状态（响应更快） |

### 14.11 v3 配置项

```bash
# === RCE ===
SAFETY_RCE_ALLOW_SAFE_COMMANDS=true
SAFETY_RCE_MAX_SLEEP=30
SAFETY_RCE_MAX_OUTPUT=1024

# === SSRF ===
SAFETY_SSRF_ALLOW_PUBLIC=true
SAFETY_SSRF_BLOCK_PRIVATE=true
SAFETY_SSRF_BLOCK_METADATA=true

# === XSS ===
SAFETY_XSS_ALLOW_ALERT=true
SAFETY_XSS_USE_BROWSER=true

# === SQL ===
SAFETY_SQLI_MAX_ROWS=3
SAFETY_SQLI_SANITIZE=false

# === 通用 ===
SAFETY_LLM_DECISION=true
SAFETY_AUDIT_ALL_DENIED=true
```

---

## 15. 性能与并发调优

### 15.1 关键指标

| 指标 | 目标值 | 监控位置 |
|---|---|---|
| 单 Worker CPU | < 1 核 | cgroup |
| 单 Worker 内存 | < 2GB | cgroup |
| 整体 LLM RPS | ≤ 30 | 令牌桶 |
| 整体 HTTP RPS | ≤ 200 | 令牌桶 |
| SQLite 锁等待 | < 1s | PRAGMA |
| nuclei 模板数 | ≤ 6000 | 启动加载 |
| 任务并发 | 15 | asyncio.Semaphore |

### 15.2 调优策略

```python
# app/config.py - 性能相关
class PerformanceSettings(BaseSettings):
    # Worker
    worker_max_concurrent: int = 15
    worker_max_rounds: int = 80
    worker_tool_timeout: int = 300
    worker_quick_probe_timeout: int = 10

    # 限速
    rate_limit_global_rps: int = 200
    rate_limit_per_worker_rps: int = 30
    rate_limit_per_target_rps: int = 5

    # LLM
    llm_max_tokens_per_call: int = 4096
    llm_max_total_tokens_per_target: int = 200000
    llm_max_cost_usd_per_target: float = 1.0

    # nuclei
    nuclei_rate_limit: int = 60
    nuclei_bulk_size: int = 10
    nuclei_concurrency: int = 10

    # SQLite
    sqlite_wal: bool = True
    sqlite_busy_timeout: int = 5000
    sqlite_cache_size: int = -20000  # 20MB
```

### 15.3 监控指标（Prometheus）

```python
# app/utils/metrics.py
from prometheus_client import Counter, Histogram, Gauge

WORKER_ACTIVE = Gauge("hunter_worker_active", "Active workers")
FINDINGS_TOTAL = Counter("hunter_findings_total", "Findings", ["vuln_type", "severity"])
LLM_TOKENS = Counter("hunter_llm_tokens_total", "LLM tokens", ["provider", "direction"])
LLM_LATENCY = Histogram("hunter_llm_latency_seconds", "LLM latency")
TOOL_DURATION = Histogram("hunter_tool_duration_seconds", "Tool duration", ["tool"])
TARGET_QUEUE_SIZE = Gauge("hunter_target_queue_size", "Queue size")
```

---

## 16. Docker 镜像与编排

### 16.1 Dockerfile（多阶段，项目根目录，基线已有）

```dockerfile
# Stage 1: 构建 Vue 前端（node:20-slim）
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build            # 产物在 /fe/../web/dist → /web/dist

# Stage 2: Python 应用 + 全套安全工具（python:3.12-slim）
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 系统工具 + 挖洞常用工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap python3-pip jq dnsutils iputils-ping netcat-openbsd whatweb \
    && rm -rf /var/lib/apt/lists/*

# sqlmap：官方 PyPI 月度版（构建不依赖 git clone GitHub，国内更稳）
RUN pip install --no-cache-dir sqlmap

# ProjectDiscovery 工具：nuclei + httpx（官方 release 二进制，TARGETARCH 由 buildkit 注入）
ARG TARGETARCH
RUN set -eux; \
    NUCLEI_VER=3.3.7; HTTPX_VER=1.6.9; \
    cd /tmp; \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" -O nuclei.zip; \
    wget -q "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" -O httpx.zip; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin/; \
    unzip -o httpx.zip httpx -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx; \
    rm -f /tmp/*.zip; \
    apt-get purge -y unzip; rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN nuclei -update-templates -silent || true   # 更新 nuclei 模板（失败不阻断构建）
COPY . .
COPY --from=frontend /web/dist /app/web/dist   # 拷入前端构建产物

RUN mkdir -p /work /app/data
ENV WORKER_WORK_ROOT=/work \
    DB_PATH=/app/data/hunter.db

EXPOSE 18800
CMD ["sh", "/app/scripts/boot.sh"]   # 看门狗：健康检查失败自动重启
```

> **注意**：`DB_PATH=/app/data/hunter.db` 为固定约定（R-005），数据必须挂 volume，严禁把数据放在容器可写层。

### 16.2 docker-compose.yml（volume 命名/路径约定）

```yaml
services:
  hunter:
    build: .
    image: hunter:latest
    container_name: hunter
    ports:
      - "${HUNTER_HOST_PORT:-18800}:18800"   # 宿主机端口:容器端口（.env 可改）
    env_file:
      - .env
    environment:
      - DB_PATH=/app/data/hunter.db
      - WORKER_WORK_ROOT=/work
    volumes:
      - hunter_data:/app/data        # SQLite + 证据持久化（重启恢复依赖，勿删）
      - hunter_work:/work            # worker 临时工作区
    restart: unless-stopped      # 崩溃自动重启，从 DB 恢复任务状态

volumes:
  hunter_data:
  hunter_work:
```

> **⚠️ 数据导入关键**：volume 名 `hunter_data` / `hunter_work`、挂载路径 `/app/data` / `/work` 为固定约定。Compose 会自动加项目名前缀（目录名为 `hunter` 时卷名即 `hunter_data`），所以导入旧部署数据时目标是 `hunter_data`（见 §21.3 方式 A）。

### 16.3 容器入口（scripts/boot.sh，基线已有）

- 启动 `uvicorn app.main:app --host 0.0.0.0 --port 18800`；
- 启动前自动修复 `websockets < 13` 的兼容性问题（防 uvicorn ImportError）；
- 每 20s 健康检查 `GET /health`，连续 3 次失败 → 采集运行时诊断（SIGUSR1 触发）→ 退出让 Docker 自动重启；
- 数据库初始化（`init_db`）在 `app.main` 启动时完成（§4.3）。

---

## 17. 一键安装与升级

### 17.1 setup.sh

```bash
#!/bin/bash
# scripts/setup.sh
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Hunter 安装向导 ===${NC}"

# 1. 检查 Docker
if ! command -v docker &>/dev/null; then
    echo -e "${RED}未检测到 Docker${NC}"
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo -e "${RED}需要 Docker Compose v2${NC}"
    exit 1
fi

# 2. 复制 .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}已生成 .env，请编辑填入 API Key${NC}"
fi

# 3. 交互式填 LLM_API_KEY
if ! grep -q "^LLM_API_KEY=.\+" .env; then
    echo -n "请输入 LLM API Key（必填）: "
    read -s LLM_KEY
    echo
    sed -i "s|^LLM_API_KEY=.*|LLM_API_KEY=${LLM_KEY}|" .env
fi

# 4. FOFA Key（可选）
echo -n "请输入 FOFA Key（直接回车跳过）: "
read FOFA_KEY
if [ -n "$FOFA_KEY" ]; then
    sed -i "s|^FOFA_KEY=.*|FOFA_KEY=${FOFA_KEY}|" .env
fi

# 5. 生成高强度令牌
TOKEN=$(openssl rand -hex 32)
sed -i "s|^HUNTER_API_TOKEN=.*|HUNTER_API_TOKEN=${TOKEN}|" .env

# 6. 构建并启动
echo -e "${YELLOW}开始构建镜像（首次 5-15 分钟）...${NC}"
docker compose build

docker compose up -d

echo -e "${GREEN}=== 安装完成 ===${NC}"
echo -e "访问地址: ${GREEN}http://localhost:18800${NC}"
echo -e "管理令牌: ${GREEN}${TOKEN}${NC}"
echo -e "请妥善保存令牌！"
```

### 17.2 upgrade.sh

```bash
#!/bin/bash
# scripts/upgrade.sh
set -e

echo "=== Hunter Pro 升级 ==="
git pull  # 或重新下载代码
docker compose build --no-cache
docker compose down
docker compose up -d
docker compose logs -f --tail=50 hunter
```

---

## 18. OpenAPI 与 SDK

### 18.1 FastAPI 自动生成

FastAPI 自动提供：
- `/docs` — Swagger UI
- `/redoc` — ReDoc
- `/openapi.json` — OpenAPI 3.1 Schema

### 18.2 关键端点

| 方法 | 路径 | 用途 | 权限 |
|---|---|---|---|
| POST | `/api/v1/auth/login` | 登录获取 JWT | 公开 |
| GET | `/api/v1/auth/tokens` | 列出令牌 | admin |
| POST | `/api/v1/auth/tokens` | 创建令牌 | admin |
| GET | `/api/v1/tasks` | 任务列表 | reader+ |
| POST | `/api/v1/tasks` | 创建任务 | operator+ |
| GET | `/api/v1/tasks/{id}` | 任务详情 | reader+ |
| POST | `/api/v1/tasks/{id}/start` | 启动任务 | operator+ |
| POST | `/api/v1/tasks/{id}/pause` | 暂停任务 | operator+ |
| DELETE | `/api/v1/tasks/{id}` | 删除任务 | admin |
| GET | `/api/v1/findings` | Finding 列表 | reader+ |
| GET | `/api/v1/findings/{id}` | Finding 详情 | reader+ |
| POST | `/api/v1/findings/{id}/approve` | 通过 | operator+ |
| POST | `/api/v1/findings/{id}/reject` | 打回 | operator+ |
| GET | `/api/v1/findings/{id}/export.{format}` | 导出报告 | reader+ |
| GET | `/api/v1/workers` | Worker 状态 | reader+ |
| POST | `/api/v1/emergency/activate` | 紧急停止 | admin |
| GET | `/api/v1/audit` | 审计日志 | admin |
| GET | `/api/v1/settings` | 查看设置 | admin |
| PUT | `/api/v1/settings/{key}` | 修改设置 | admin |
| WS | `/api/v1/ws` | 实时事件流 | reader+ |

### 18.3 SDK 示例

```python
# sdk/python/hunter.py
from hunter import Client

client = Client(base_url="http://localhost:18800", token="...")

# 创建任务
task = client.tasks.create(
    name="edu-test",
    mode="edu",
    source="fofa",
    collect_method="fofa_syntax",
    query='body="管理" && domain="edu.cn"',
    vuln_types=["sqli", "rce", "unauthorized_access"],
)

# 启动任务
client.tasks.start(task.id)

# 流式监听事件
async for event in client.websocket.stream():
    print(event)

# 导出报告
report = client.findings.export(finding_id=123, format="markdown")
print(report.text)
```

---

## 19. 监控、运维与备份

### 19.1 健康检查

```python
# app/main.py
@app.get("/health")
async def health():
    async with async_session() as s:
        db_ok = await s.execute("SELECT 1")
        return {
            "status": "ok",
            "db": "ok" if db_ok else "down",
            "version": __version__,
            "uptime": int(time.time() - START_TIME),
            "active_workers": worker_pool.active_count(),
        }
```

### 19.2 备份脚本

```bash
#!/bin/bash
# scripts/backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR=/backup/hunter/$DATE

mkdir -p $BACKUP_DIR

# 备份 SQLite（在线备份）
sqlite3 /var/lib/docker/volumes/hunter_data/_data/hunter.db \
    ".backup '$BACKUP_DIR/hunter.db'"

# 备份审计日志
tar czf $BACKUP_DIR/audit.tar.gz \
    /var/lib/docker/volumes/hunter_data/_data/audit/

# 备份报告
tar czf $BACKUP_DIR/reports.tar.gz \
    /var/lib/docker/volumes/hunter_data/_data/reports/

# 上传到 S3（可选）
aws s3 cp $BACKUP_DIR s3://my-bucket/hunter/$DATE/ --recursive

# 清理 30 天前的
find /backup/hunter -mtime +30 -delete
```

### 19.3 监控告警

```yaml
# monitoring/prometheus.yml
scrape_configs:
  - job_name: 'hunter'
    static_configs:
      - targets: ['localhost:18800']
    metrics_path: /metrics
```

```yaml
# monitoring/alerts.yml
groups:
- name: hunter
  rules:
  - alert: EmergencyStopActivated
    expr: hunter_emergency_active == 1
    annotations:
      summary: "紧急制动已激活"

  - alert: WorkerStuck
    expr: time() - hunter_worker_last_heartbeat > 300
    annotations:
      summary: "Worker {{ $labels.id }} 卡住超过 5 分钟"

  - alert: LLMCostOverBudget
    expr: rate(hunter_llm_cost_total[1h]) > 10
    annotations:
      summary: "LLM 成本超预算"
```

---

## 20. 开发路线图 (MVP → GA)

> **现状**：代码基线为**自有迭代产物**（v0.x 原型 → v1.0 → v1.1 → v1.2 持续演进），后端 ReAct 全链路、前端 Vue 3、Docker 编排均为**已有可运行代码**。MVP 不是"从零开发"，而是**自有项目迭代 + 旧数据导入打通 + 部署验证**，节奏比全新项目快得多。

### Phase 1: MVP（核心闭环，当前阶段）

| 步骤 | 任务 | 状态 |
|---|---|---|
| S1 | 品牌统一：全局品牌规范为 Hunter（后端/前端/Docker/脚本/README） | 🔄 进行中 |
| S2 | 旧数据导入验证：复制旧部署卷的 `hunter.db`，启动后自动迁移补齐列/索引（§4.3/§21.5） | ⬜ |
| S3 | Docker 部署：`docker compose up -d --build` 一键起，复制卷即得历史数据（§16/§21） | ⬜ |
| S4 | 核心闭环验收：任务管理 + 多引擎目标采集 + Worker ReAct 扫描 + Finding 复审 + 报告导出 + 看板 | ⬜ |
| S5 | setup.sh 一键安装 + 文档定稿 | ⬜ |

### Phase 2: 增强（基于基线增量）

| 步骤 | 任务 |
|---|---|
| E1 | 多引擎补强（Quake/Hunter/ZoomEye/Shodan/Censys 配置与管理页） |
| E2 | 通杀 Hunter 体验打磨 + 情报库沉淀增强 |
| E3 | LLM 多供应商池 + 成本监控 |
| E4 | 看板图表增强（ECharts）+ 告警通知 |

### Phase 3: GA

| 步骤 | 任务 |
|---|---|
| G1 | PDF/JSON 报告 + 批量导出 |
| G2 | 紧急熔断 + 熔断器 + 扫描限速（§14 远期项落地，须守 §4 红线） |
| G3 | 性能调优 + 监控 |
| G4 | 完整文档 + SDK + E2E 测试 + Beta 发布 |

### Phase 4: 加固（持续）

- 多角色 RBAC（新增用户表，红线内允许，§0.5）
- nuclei 模板定制 / WAF 集成 / 反爬绕过（UA 池、代理池）
- 漏洞库联动（CNNVD / CNVD / NVD）
- 团队协作（多租户、消息通知）

---

## 附录 A: 关键 Prompt 模板

### A.1 Worker 系统 Prompt

```python
WORKER_SYSTEM_PROMPT = """你是安全研究员 Agent，目标是对 {target_url} 进行漏洞挖掘。

# 目标信息
- URL: {target_url}
- IP: {target_ip}
- Server: {target_server}
- 标题: {target_title}
- 技术栈: {target_tech}
- 归属: {target_org}

# 任务
在 {max_rounds} 轮内，使用提供的工具识别并验证漏洞。
允许的漏洞类型：{vuln_types}

# 工作准则
1. **先侦察后利用**：先 httpx/nmap/whatweb 摸清目标，再针对可疑点深挖
2. **真实证据**：每个漏洞必须有可复现的 HTTP 请求/响应证据
3. **无破坏性测试**：仅验证存在性，不删除/修改数据
4. **限速**：同一目标 ≤5 req/s，全局 ≤200 req/s
5. **二次确认**：执行 PoC/exp 类工具需用户授权

# 输出格式
每轮返回 JSON：
```json
{{
  "thought": "思考当前进度与下一步",
  "action": "tool_name 或 'finish'",
  "action_input": {{...}},
  "finding": null | {{
    "vuln_type": "sqli|xss|rce|unauth|file_upload|idor|captcha_bypass",
    "severity": "critical|high|medium|low",
    "title": "...",
    "evidence": "HTTP 请求/响应",
    "payload": "...",
    "reproduction": "步骤",
    "impact": "危害",
    "remediation": "修复"
  }}
}}
```

# 禁止
- 不要尝试登录非授权账号
- 不要写入/修改目标数据
- 不要执行破坏性命令 (rm/dd/mkfs)
- 不要尝试内网穿透

{intel_context}
"""
```

### A.2 自然语言 → FOFA 翻译

```python
INTENT_TO_FOFA_PROMPT = """你是 FOFA 语法专家，将自然语言意图翻译为 FOFA 查询语句。

支持的字段：
- title= 网页标题
- body= 网页正文
- domain= 域名 (如 .edu.cn)
- host= 主机名
- org= 所属机构
- cert.subject.org= 证书机构
- port= 端口
- country= 国家
- icon= 图标 hash
- header= HTTP 头

逻辑符：&& (且) || (或) != (非)

示例：
- "全国高校统一身份认证" → body="统一身份认证" && domain="edu.cn"
- "暴露的 Docker API" → port="2375" && country="CN"
- "Spring Boot Actuator" → body="actuator" && server="Apache Tomcat"

用户输入：{intent}

只输出 FOFA 查询，不要解释。"""
```

### A.3 Reviewer Prompt

```python
REVIEWER_PROMPT = """你是资深安全研究员，审查 AI 漏洞挖掘 Agent 提交的结果。

# 审查标准
✅ **PASS**（送人工复审）：
   - 可稳定复现（提供完整 HTTP 请求包）
   - 实际危害（非理论）
   - 证据完整（含响应内容/截图替代数据）

⚠️ **NEEDS_DEEP**（回炉深挖）：
   - 疑似漏洞但证据不足
   - 需要更换 payload 重试
   - nuclei 模板误报需人工验证

❌ **REJECT**（直接丢弃）：
   - 误报 / 模板缺陷
   - 无危害的扫描器噪音
   - 路径不存在 / 已被修复
   - WAF 拦截造成的假阳性

# 输入
候选 Finding：
{json.dumps(finding, ensure_ascii=False, indent=2)}

目标信息：
{json.dumps(target, ensure_ascii=False, indent=2)}

# 输出
严格 JSON：
```json
{{
  "verdict": "pass" | "needs_deep" | "reject",
  "score": 0.0-10.0,
  "reason": "具体理由（指出证据缺口或确认点）",
  "deep_dive_hint": "如果 needs_deep，下一步具体要做什么"
}}
```"""
```

### A.4 通杀 Hunter Prompt

```python
HUNTER_KILLER_PROMPT = """你是漏洞批量验证专家。给定一个确认的漏洞，判断能否"一打一片"。

# 输入
原始 Finding：
{finding}

# 任务
1. 提取漏洞指纹（哪个组件/版本/路径/参数/Payload）
2. 在已有目标库中检索同指纹目标
3. 对每个候选目标，生成验证脚本（同 Payload 复用）
4. 输出验证计划

# 输出
```json
{{
  "fingerprint": {{
    "component": "...",
    "version": "...",
    "endpoint_pattern": "...",
    "payload_template": "...",
    "detection_signature": "..."
  }},
  "estimated_targets": N,
  "verification_plan": [
    {{"target": "...", "expected_result": "..."}}
  ],
  "feasible": true|false,
  "risk_assessment": "..."
}}
```"""
```

---

## 附录 B: nuclei 模板适配指南

### B.1 模板结构

```yaml
# /data/nuclei-templates/vulnerabilities/sqli/mysql-error-based.yaml
id: mysql-error-based-sqli
info:
  name: MySQL Error Based SQL Injection
  author: pdteam
  severity: high
  description: |
    Detects MySQL error-based SQL injection vulnerabilities.
  reference:
    - https://example.com/sqli-ref
  tags: sqli,mysql,error-based

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Duplicate entry"
          - "version()"
      - type: status
        status:
          - 500
```

### B.2 自定义模板适配

```python
# app/core/worker/tools/nuclei.py
async def load_custom_templates(self):
    """加载用户自定义模板"""
    custom_dir = "/data/nuclei-custom/"
    if os.path.exists(custom_dir):
        for f in os.listdir(custom_dir):
            if f.endswith((".yaml", ".yml")):
                # 校验
                template = yaml.safe_load(open(f"{custom_dir}/{f}"))
                if self._validate_template(template):
                    self.templates.append(f"{custom_dir}/{f}")
```

### B.3 CVE 模板筛选

```python
def get_cve_templates(cve_id: str) -> list[str]:
    """根据 CVE ID 筛选所有相关 nuclei 模板"""
    pattern = cve_id.lower().replace("cve-", "")
    return glob(f"/data/nuclei-templates/**/*{pattern}*", recursive=True)

# 用法
templates = get_cve_templates("CVE-2021-44228")  # Log4Shell
await nuclei.execute({"target": "...", "templates": templates})
```

---

## 版权与许可

```
Hunter — AI 自主漏洞挖掘平台
Copyright (c) 2026 Hunter 项目
许可协议：CC BY-NC 4.0（署名-非商业性使用-相同方式共享）
仅供授权安全测试与研究 · 禁止任何商业用途
请遵守当地法律法规
```

---

## 21. 数据导入与兼容（旧部署数据直接可用）

> **本章面向已经长期运行 Hunter 旧部署、积累了大量漏洞数据的用户**。设计决策（R-005）：Hunter **不迁移、不转换、不重构**，schema 采用 UUID 主键 + 固定表结构，兼容性由持久层自动迁移兜底。用户只需把旧部署的数据卷复制到 Hunter，历史任务 / 目标 / Finding / 复审 / 通杀 / 情报**立即可见可用**。

### 21.1 为什么数据能直接用

Hunter 的持久层设计从一开始就为"数据直接可用"做了两件事：

1. **schema 采用 UUID 主键（`String(32)`）+ 固定 8 张核心表**（`tasks/targets/findings/reviews/killsweeps/intel/task_events/system_settings`，见 §4.2）：主键跨部署稳定、不依赖自增序列，数据文件可直接迁移。
2. **兼容性由持久层自动迁移兜底**（§4.3 `init_db()`）：启动时自动执行——缺列自动补齐（`ALTER TABLE ... ADD COLUMN` 带 DEFAULT，老数据零影响）、残留列自动清理（失败不阻断）、索引自动升级（先删后建，历史重复数据降级为普通索引兜底）。

因此旧部署的 `hunter.db` 无需任何手工转换即可被 Hunter 直接读写。

### 21.2 数据来源定位

旧部署的 SQLite 数据库路径取决于部署方式：

| 部署方式 | 源数据库路径 |
|---|---|
| **直接 Python 运行** | `{项目根}/data/hunter.db` |
| **Docker 部署** | volume `hunter_data` 内 `/app/data/hunter.db` |
| **setup.sh 一键脚本** | 通常在 `~/hunter/data/hunter.db` |

**定位 Docker volume 实际挂载位置**（在旧部署所在的 Ubuntu 主机上执行）：

```bash
# 查看 volume 在宿主机的实际目录
docker volume inspect hunter_data --format '{{ .Mountpoint }}'
# 例: /var/lib/docker/volumes/hunter_data/_data
# 该目录下即为 hunter.db (+ -shm/-wal 文件)
```

### 21.3 导入方式

**方式 A（推荐）：一键导入脚本 `scripts/import-data.sh`**

脚本自动探测源/目标卷、创建目标卷、复制 `hunter.db`（含 `-wal`/`-shm`）、校验大小一致；目标卷已有数据时默认拒绝覆盖（带保护），全程不需要 sudo（避免手敲宿主机 `/var/lib/docker` 路径）：

```bash
# 在部署 Hunter 的 Ubuntu 主机上执行
bash scripts/import-data.sh                        # 自动探测源/目标卷
bash scripts/import-data.sh --from 旧部署数据卷 --to hunter_data   # 手动指定源/目标卷
bash scripts/import-data.sh --force                # 目标卷已有数据时强制覆盖（慎用）
bash scripts/import-data.sh --dry-run              # 只预览不执行
```

参数说明：

| 参数 | 说明 |
|---|---|
| `--from <卷名>` | 指定源数据卷（旧部署所在卷），缺省自动探测 |
| `--to <卷名>` | 指定目标数据卷（Hunter 卷），缺省 `hunter_data` |
| `--force` | 目标卷已有数据时强制覆盖（默认拒绝，保护已有数据） |
| `--dry-run` | 只打印将要执行的操作，不实际复制 |

**方式 B：手动复制 volume 数据目录（手工）**

在同时拥有旧部署与 Hunter 部署的宿主机上执行：

```bash
# 1. 确认两个卷的实际路径
AUTO_VOL=$(docker volume inspect 旧部署数据卷 --format '{{ .Mountpoint }}')
HUNT_VOL=$(docker volume inspect hunter_data --format '{{ .Mountpoint }}')
echo "$AUTO_VOL  ->  $HUNT_VOL"

# 2. 复制 db 文件（先停 Hunter 容器，避免写入冲突）
docker compose -f /path/to/hunter/docker-compose.yml down
sudo cp "$AUTO_VOL/hunter.db" "$HUNT_VOL/hunter.db"
# 如存在 -wal/-shm，一并复制（或复制后删除，让 SQLite 自动重建）
sudo cp "$AUTO_VOL/hunter.db-wal" "$HUNT_VOL/" 2>/dev/null || true
sudo cp "$AUTO_VOL/hunter.db-shm" "$HUNT_VOL/" 2>/dev/null || true

# 3. 启动 Hunter
docker compose -f /path/to/hunter/docker-compose.yml up -d
```

**方式 C：docker cp（容器间复制）**

```bash
# 先把旧部署容器里的 db 拷到宿主机，再拷进 Hunter 容器
docker cp hunter:/app/data/hunter.db /tmp/hunter.db
docker cp /tmp/hunter.db hunter:/app/data/hunter.db
# 重启 Hunter 使数据库连接重新加载
docker restart hunter
```

**方式 D：绑定挂载（bind mount，共用一份数据）**

如果希望 Hunter **直接读写旧部署原数据目录**（同一台机器，共用一份数据），修改 Hunter 的 `docker-compose.yml`：

```yaml
services:
  hunter:
    volumes:
      - /var/lib/docker/volumes/旧部署数据卷/_data:/app/data   # 直接指向旧部署数据卷
      - hunter_work:/work
```

> ⚠️ 方式 D 会让两套部署共享同一数据库，**同一时刻只允许其中一个实例运行**（SQLite 不支持多进程并发写）；执行前需先停止旧容器。

### 21.4 兼容性保证

Hunter 的 SQLAlchemy 模型（`app/db/models.py`）、表名、字段、主键（UUID `String(32)`）、索引与旧库保持**逐字段一致**：

| 项目 | 约定 | 说明 |
|---|---|---|
| DB 文件名 | `hunter.db` | 默认库文件，自动采用机制以此为准 |
| 挂载路径 | `/app/data` | Docker 内固定路径（volume `hunter_data:/app/data`） |
| 主键策略 | UUID `String(32)` | 跨部署稳定，不依赖自增序列 |
| 表 | `tasks/targets/findings/reviews/killsweeps/intel/task_events/system_settings` | 固定 8 张核心表（§4.2） |
| 表名/字段 | 见 `app/db/models.py` | 固定不变 |
| 时间存储 | UTC naive datetime | 统一约定 |
| `PRAGMA user_version` | 统一管理 | 升级脚本放 `app/db/migrations/` |

**自动迁移兜底**（§4.3 `init_db()`）：启动时自动执行 `create_all` 建缺失新表、`_auto_migrate` 补齐缺失列 / 清理残留列、`_ensure_unique_indexes` / `_ensure_secondary_indexes` 升级索引，老数据零人工处理。

> **Hunter 开发规范：不得修改任何既有表的列名 / 类型 / 约束 / 默认值；新增功能只允许"新增表 + 新增列（带默认值）"**（§4 兼容性红线）。

### 21.5 验证清单

```bash
# 1. 启动日志：无迁移错误
docker compose logs hunter | grep -i -E "migrat|error"

# 2. 数据完整性：旧库与 Hunter 库对比
sqlite3 /var/lib/docker/volumes/旧部署数据卷/_data/hunter.db \
  "SELECT 'tasks' AS 表名, COUNT(*) FROM tasks
   UNION ALL SELECT 'targets', COUNT(*) FROM targets
   UNION ALL SELECT 'findings', COUNT(*) FROM findings
   UNION ALL SELECT 'killsweeps', COUNT(*) FROM killsweeps"
# 在 Hunter 卷中执行相同 SQL，数字应完全一致

# 3. 页面验证
#    控制台（任务列表/看板统计）出现旧部署历史任务
#    Finding 复审页出现历史漏洞，复审状态正确显示

# 4. 新增任务验证（写路径）
#    在 Hunter 中新建一个扫描任务，应正常执行并写入同一数据库
```

### 21.6 风险与缓解

| 风险 | 缓解 |
|---|---|
| 旧容器未停止导致 WAL 不一致（`-wal`/`-shm` 未落盘） | 先停旧容器（`docker stop`）再复制数据 |
| 目标卷已有数据被覆盖 | `import-data.sh` 默认拒绝覆盖已有数据的卷，需显式 `--force` |
| `-wal`/`-shm` 未复制导致日志不一致 | 复制后删除旧 `-wal`/`-shm`，SQLite 自动从主库重建（推荐） |
| db 被占用（"database is locked"） | 关闭占用实例（可能旧部署还在运行）；或删除 `-wal`/`-shm` 后重启 |
| 两套部署共用同一 db 并发写 | 方式 D 时同一时刻只允许一个实例运行 |
| Hunter 升级改了 schema 导致旧库不可读 | 遵循 §21.4 开发规范；升级前备份 db |
| 大库（90MB+）复制耗时 | 推荐在宿主机直接 `cp`（比 docker cp 快），或先停容器再复制 |

### 21.7 备份与恢复

```bash
# 备份（建议每周 + 每次大升级前）：将 hunter_data 卷整体备份到宿主机目录
docker run --rm -v hunter_data:/v -v $(pwd):/b alpine cp -a /v/. /b/hunter_data_backup/

# 恢复：反向复制即可（先停 Hunter 容器）
docker compose stop hunter
docker run --rm -v hunter_data:/v -v $(pwd):/b alpine sh -c "rm -rf /v/* && cp -a /b/hunter_data_backup/. /v/"
docker compose start hunter
```

### 21.8 故障排查

**Q：导入后页面没有历史数据**
```bash
# 检查 Hunter 实际使用的 db 路径与文件大小
docker exec hunter ls -la /app/data/
# 应为 hunter.db 且大小与源库一致（约 90MB）
# 若容器内是其它文件名，说明 DB 路径配置不一致，检查 .env 中 DB 相关配置
```

**Q：报错 "database is locked"**
```bash
# 有另一实例占用 db（可能旧部署还在运行）
# 关闭其中一个实例；或删除 -wal/-shm 后重启
docker restart hunter
```

**Q：db 损坏 / 启动失败**
```bash
# 用备份恢复；或从旧部署数据卷重新复制一份
docker compose down
sudo cp /var/lib/docker/volumes/旧部署数据卷/_data/hunter.db \
        /var/lib/docker/volumes/hunter_data/_data/hunter.db
docker compose up -d
```

---

## 版权与许可

```
Hunter — AI 自主漏洞挖掘平台
Copyright (c) 2026 Hunter 项目
许可协议：CC BY-NC 4.0（署名-非商业性使用-相同方式共享）
仅供授权安全测试与研究 · 禁止任何商业用途
请遵守当地法律法规
```