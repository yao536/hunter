# Hunter

> 一台机器，7×24 小时不停歇的 AI 漏洞挖掘流水线。
> 你把目标交给它，醒来只做一件事：**裁决**。

Hunter 是面向个人/小团队的自主漏洞挖掘平台。它把「目标搜集 → 侦察 → 实打 → 初审 → 人工复审 → 报告」整条流水线串起来：AI Agent 负责干活，你只对 AI 初审后够格的漏洞做最终裁决，几分钟内完成一批。

**个人自用项目**：Docker 一键部署、复制数据文件即用、数据全部本地持久化。

---

## 系统怎么工作

```
                ┌──────────────────────────────┐
  FOFA / 手动    │  Recon Agent  侦察 / 目标采集   │
  ────────────▶ │  自动搜 · 探活 · 评分 · 归属     │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │  Attacker Agent  攻击 1:1      │
                │  LLM 自主决策 · 真实工具链发包   │
                │  nmap / nuclei / sqlmap / httpx│
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │  Auditor Agent  极理性初审      │
                │  只放「实际可利用+实锤危害」的洞  │
                └───────┬──────────────┬────────┘
                        │              │
                不够格的回炉深挖     够格的进人工复审
                        │              ▼
                        │      ┌────────────────┐
                        │      │  你 · 裁决       │
                        │      │  调级/通过/打回   │
                        │      └───────┬────────┘
                        │              ▼
                        │      ┌────────────────┐
                        └─────▶│ 报告 · 提交清单    │
                               └────────────────┘
```

四个角色各司其职：

| 角色 | 干什么 |
|---|---|
| **Recon**（侦察） | 从 FOFA 等测绘引擎自动产目标，或吃你贴的手动清单；探活、预筛、评分、归属标注后入队 |
| **Attacker**（攻击） | 每个目标一个 Agent，LLM 自主侦察 + 真实调用工具链，出洞即上报 |
| **Auditor**（审核） | 极理性 AI 初审：过滤半成品/误报，只把够格的洞送到你面前 |
| **你** | 几分钟裁决：调级 / 通过 / 打回深挖 / 编辑 / 标记已提交 |

平台还带通杀联动、情报沉淀、全局漏洞库、归属单位离线反查、内置 WAF 与多角色鉴权。

---

## 快速部署

需要 Docker + Docker Compose v2（任意系统，推荐 Linux 2C4G / 磁盘 20G+）。

```bash
# 1. 装 Docker（已装可跳过）
curl -fsSL https://get.docker.com | sh && sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker

# 2. 一键部署（交互式引导）
cd <本仓库目录>
bash scripts/setup.sh
```

向导会：检查环境 → 收集 LLM API Key（必填）/ FOFA Key（推荐）→ 生成访问令牌 → 构建镜像并启动 → 打印控制台地址。

首次构建需拉基础镜像 + 编译前端 + 安装工具链，约 5~15 分钟。完成后浏览器打开 `http://<服务器IP>:18800/`，用打印的令牌登录。

> 云服务器记得在安全组放行 18800 端口。

**不用向导也行**：

```bash
cp .env.example .env        # 至少填 LLM_API_KEY，建议 HUNTER_API_TOKEN
docker compose up -d --build
```

---

## 最小必填配置

| 变量 | 说明 |
|---|---|
| `LLM_API_KEY` | **必填**。大模型 API Key（DeepSeek/OpenAI/Claude/通义/Kimi 均可） |
| `LLM_BASE_URL` / `LLM_MODEL` | 默认 DeepSeek：`https://api.deepseek.com/v1` / `deepseek-chat` |
| `FOFA_KEY` | 推荐。自动资产搜集 |
| `HUNTER_API_TOKEN` | **强烈建议**。控制台全权限令牌，不设则任何人可访问 |

完整参数见 [`.env.example`](.env.example)，都带注释；也支持在控制台「设置」页直接填 LLM/FOFA Key（存库，优先级高于 .env）。

---

## 数据迁移 / 备份（复制一份，不挂旧卷）

数据全部持久化在 volume `hunter_data`（SQLite + 证据）与 `hunter_work`（工作区），**升级重启不丢数据**。

如果你之前有旧部署积累的数据（任务/目标/Finding/复审记录），推荐**复制一份数据给 Hunter**，而不是把旧卷直接挂给新容器——新旧完全隔离，旧卷留作备份：

```bash
bash scripts/import-data.sh                        # 自动探测源 → 复制到 hunter_data 卷
bash scripts/import-data.sh --from <旧卷名或目录>   # 指定来源
bash scripts/import-data.sh --dry-run              # 先预览
```

Hunter 的数据库与旧版部署**表结构完全一致**，复制进来启动即用（启动时自动采用，缺失字段自动补齐，无需手动迁移）。

备份数据卷：

```bash
docker run --rm -v hunter_data:/data -v "$(pwd)":/backup alpine \
  tar czf /backup/hunter-data-$(date +%Y%m%d).tar.gz -C /data .
```

---

## 使用流程

1. 登录控制台 → **新建挖掘任务**
2. 填任务名、模式（教育行业 / 企业）、目标来源（FOFA 自动搜 / 手动清单 / 单站协作）
3. 搜集方式二选一：
   - 会写语法 → 直接粘 FOFA 语句（如 `body="管理" && org="China Education and Research Network Center"`）
   - 不会 → 用大白话说要什么（"找高校统一身份认证登录系统"），Recon 自动翻译并演化语法
4. 启动任务，去干别的；看板实时显示每个目标在做什么
5. 有「待复审」红点后进去裁决；通过的洞进提交清单，一键导出报告

---

## 运维

```bash
docker compose logs -f hunter      # 日志
docker compose restart hunter      # 重启
docker compose down                # 停止（数据留在卷里）
docker compose up -d --build       # 更新代码后重建
```

容器 `restart: unless-stopped` 自动拉起；`boot.sh` 内置健康守护，服务挂死会自动重启而非僵死。

---

## 常见问题

- **模型不支持 function calling？** 设置 `HUNTER_TOOL_COMPAT=prompt` 强制提示词模拟工具调用；默认 `auto` 会在报错时自动切换。
- **重启后任务不续跑？** 确认 `HUNTER_RESTORE_ON_STARTUP=1`（默认开）。
- **想换测绘引擎？** 设置页可配 360 Quake / Hunter / ZoomEye / Shodan / Censys，自动把 FOFA 语法翻译过去。

---

## 许可

本项目采用 [CC BY-NC 4.0](./LICENSE)（署名-非商业性使用）：可自由使用/修改/分发，**禁止商用**。

---

*仅供已获授权的安全测试与研究。请遵守当地法律法规。*
