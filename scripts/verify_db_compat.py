"""R-005 兼容性验证：模拟 Hunter 旧库（缺列/旧索引/残留列）→ 跑 Hunter init_db()。

用法：python scripts/verify_db_compat.py [--db <path>]
验证点：
  1. 旧库缺列 → 自动 ALTER TABLE ADD COLUMN（带 DEFAULT，老数据不丢）
  2. 旧唯一索引形态 → 升级/重建为全局形态
  3. 废弃残留列 user_decision → 自动清理
  4. 老数据完好 + 新代码可插入新字段
"""
import asyncio
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import text

DB = os.environ.get("TEST_DB") or os.path.join(tempfile.gettempdir(), "hunter_compat_test.db")


async def make_old_db():
    """手工构造一个'Hunter 早期版本'形态的库：只含核心表 + 部分列 + 老索引 + 残留列。"""
    import aiosqlite

    db = DB
    if os.path.exists(db):
        os.remove(db)
    conn = await aiosqlite.connect(db)
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.executescript(
        """
        CREATE TABLE tasks (
            id TEXT(32) PRIMARY KEY, name VARCHAR(200) NOT NULL,
            src_type VARCHAR(20) DEFAULT 'edusrc', vuln_types JSON,
            target_source VARCHAR(20) DEFAULT 'fofa', fofa_query TEXT,
            manual_targets JSON, src_rules TEXT, model_config JSON,
            fofa_config JSON, status VARCHAR(20) DEFAULT 'created',
            concurrency INTEGER DEFAULT 3, created_at DATETIME, updated_at DATETIME
        );
        CREATE TABLE targets (
            id TEXT(32) PRIMARY KEY, task_id TEXT(32), url VARCHAR(500),
            host VARCHAR(200), ip VARCHAR(64), org VARCHAR(300), title VARCHAR(500),
            source VARCHAR(20) DEFAULT 'fofa', is_edu BOOLEAN DEFAULT 0,
            status VARCHAR(20) DEFAULT 'queued', verdict VARCHAR(20) DEFAULT '',
            retry_count INTEGER DEFAULT 0, assigned_worker VARCHAR(20),
            heartbeat_at DATETIME, created_at DATETIME, updated_at DATETIME
        );
        CREATE TABLE findings (
            id TEXT(32) PRIMARY KEY, task_id TEXT(32), target_id TEXT(32),
            worker_id VARCHAR(50), vuln_type VARCHAR(50) NOT NULL,
            title VARCHAR(500) NOT NULL, severity_claimed VARCHAR(20),
            target_url VARCHAR(500), description TEXT, steps JSON, poc TEXT,
            raw_request TEXT, raw_response TEXT, evidence JSON,
            affected_scope TEXT, self_check JSON, dedup_key VARCHAR(128),
            status VARCHAR(20) DEFAULT 'pending_review', created_at DATETIME
        );
        CREATE TABLE reviews (
            id TEXT(32) PRIMARY KEY, finding_id TEXT(32) UNIQUE, task_id TEXT(32),
            verdict VARCHAR(20) DEFAULT 'pending', confidence VARCHAR(20),
            severity_final VARCHAR(20), score FLOAT DEFAULT 0,
            in_scope BOOLEAN DEFAULT 0, is_duplicate BOOLEAN DEFAULT 0,
            reproduced BOOLEAN DEFAULT 0, ignore_reasons JSON, downgrade_reasons JSON,
            reviewer_notes TEXT, reviewed_at DATETIME,
            user_decision VARCHAR(20) DEFAULT 'pending'   -- 残留列：新代码已弃用
        );
        CREATE TABLE killsweeps (
            id TEXT(32) PRIMARY KEY, task_id TEXT(32), origin_finding_id TEXT(32),
            product_key VARCHAR(200), product_name VARCHAR(300), vuln_type VARCHAR(50),
            vuln_summary TEXT, fofa_query TEXT, fingerprint TEXT,
            asset_count INTEGER DEFAULT 0, edu_count INTEGER DEFAULT 0,
            is_killsweep BOOLEAN DEFAULT 0, confidence VARCHAR(20),
            verified_url VARCHAR(500), verified BOOLEAN DEFAULT 0, notes TEXT,
            status VARCHAR(20) DEFAULT 'analyzing', created_at DATETIME, updated_at DATETIME
        );
        CREATE TABLE task_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT(32), agent VARCHAR(50),
            level VARCHAR(10), kind VARCHAR(50), message TEXT, payload JSON, ts DATETIME
        );
        CREATE TABLE intel (
            id TEXT(32) PRIMARY KEY, kind VARCHAR(20), match_key VARCHAR(300),
            dedup_hash VARCHAR(64), payload JSON, summary VARCHAR(500),
            source_host VARCHAR(300), source_task_id TEXT(32),
            confidence VARCHAR(20) DEFAULT 'likely', hit_count INTEGER DEFAULT 0,
            first_seen DATETIME, last_seen DATETIME
        );
        CREATE TABLE system_settings (
            id TEXT(32) PRIMARY KEY, llm JSON, fofa JSON, defaults JSON, updated_at DATETIME
        );
        -- 老形态唯一索引：同任务 host 唯一（缺 source）、findings 按 (task_id, dedup_key)
        CREATE UNIQUE INDEX ux_targets_task_host ON targets(task_id, host);
        CREATE UNIQUE INDEX ux_findings_task_dedup ON findings(task_id, dedup_key)
            WHERE dedup_key <> '';
        -- 老数据（含可读中文）
        INSERT INTO tasks (id, name, src_type, status, created_at) VALUES
            ('aaa00000000000000000000000000001', '老任务-教育SRC', 'edusrc', 'running', '2026-07-01 10:00:00');
        INSERT INTO targets (id, task_id, url, host, org, source, status) VALUES
            ('aaa00000000000000000000000000002', 'aaa00000000000000000000000000001', 'https://www.old-edu.cn', 'www.old-edu.cn', '老教育单位', 'fofa', 'done');
        INSERT INTO findings (id, task_id, target_id, worker_id, vuln_type, title, dedup_key, status) VALUES
            ('aaa00000000000000000000000000003', 'aaa00000000000000000000000000001', 'aaa00000000000000000000000000002', 'W-01', 'sqli', '老库 SQL 注入', 'old-edu-sqli', 'pending_review');
        INSERT INTO reviews (id, finding_id, task_id, verdict, user_decision) VALUES
            ('aaa00000000000000000000000000004', 'aaa00000000000000000000000000003', 'aaa00000000000000000000000000001', 'accepted', 'pending');
        INSERT INTO task_events (task_id, agent, level, kind, message) VALUES
            ('aaa00000000000000000000000000001', 'orchestrator', 'info', 'task_started', '老任务启动');
        """
    )
    await conn.commit()
    await conn.close()
    print(f"[1/5] 构造 Hunter 旧库 OK（含 1 条任务/目标/漏洞/复审/事件 + 残留列 + 旧索引）")


async def run_init():
    """调用 Hunter 的 init_db()（复用项目真实 session.py）。"""
    from app.db import session

    # 覆盖 DB_PATH 后再 import engine（session 模块在模块级建 engine）
    os.environ["DB_PATH"] = DB
    import importlib

    importlib.reload(session)
    await session.init_db()
    print("[2/5] init_db() 执行完成（create_all + 自动迁移 + 索引重建）")


async def verify():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(f"sqlite+aiosqlite:///{DB}")
    async with eng.connect() as c:
        # 3. 缺列已补
        for table, col in [
            ("reviews", "user_status"), ("reviews", "submitted"), ("reviews", "deepen_directive"),
            ("targets", "priority_score"), ("targets", "school"), ("targets", "auth_context"),
            ("findings", "owner"), ("findings", "llm_model"), ("findings", "assistant_messages"),
            ("killsweeps", "affected_table"), ("system_settings", "engines"), ("tasks", "engine"),
            ("tasks", "auth_bindings"),
        ]:
            r = (await c.exec_driver_sql(f"PRAGMA table_info({table})")).fetchall()
            names = {x[1] for x in r}
            assert col in names, f"[FAIL] {table}.{col} 未补上"
        print("[3/5] 缺列自动补齐 OK（reviews.user_status/submitted、targets.priority_score/school/auth_context、findings.owner/llm_model、killsweeps.affected_table 等 13 列）")

        # 4. 残留列已清理
        r = (await c.exec_driver_sql("PRAGMA table_info(reviews)")).fetchall()
        assert "user_decision" not in {x[1] for x in r}, "[FAIL] 残留列 user_decision 未清理"
        print("[4/5] 废弃残留列 user_decision 清理 OK")

        # 5. 老数据完好 + 新代码可写（新列 user_status/submitted 写入既有复审行）
        rows = (await c.exec_driver_sql("SELECT name, status FROM tasks")).fetchall()
        assert rows[0][0] == "老任务-教育SRC", "[FAIL] 老任务数据丢失"
        await c.execute(
            text(
                "UPDATE targets SET priority_score=9.5, priority_reason='老数据保留', "
                "school='老教育单位' WHERE host='www.old-edu.cn'"
            )
        )
        await c.execute(
            text(
                "UPDATE reviews SET user_status='passed', submitted=1, user_notes='AI 初审后被人工通过' "
                "WHERE finding_id='aaa00000000000000000000000000003'"
            )
        )
        # 索引形态验证
        idx = (await c.exec_driver_sql(
            "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name IN ('targets','findings')"
        )).fetchall()
        idxmap = {r[0]: (r[1] or "") for r in idx}
        assert "source" in idxmap.get("ux_targets_task_host", ""), "[FAIL] targets 唯一索引未升级含 source"
        assert "ON findings(dedup_key)" in idxmap.get("ux_findings_dedup_global", ""), "[FAIL] findings 全局唯一索引未建立"
        await c.commit()
    await eng.dispose()
    print("[5/5] 老数据完好 + 新字段可写 + 索引升级为全局形态 OK")


async def main():
    print("=" * 62)
    print(" R-005 数据复用兼容性验证（Hunter 旧库 → Hunter init_db）")
    print("=" * 62)
    await make_old_db()
    await run_init()
    await verify()
    print("-" * 62)
    print("[PASS] 全部通过：复制 Hunter 卷 -> 启动 Hunter -> 自动迁移补齐，老数据直接可用")
    # Windows 下 SQLite 句柄可能延迟释放，重试删除临时库
    for p in [DB, DB + "-wal", DB + "-shm"]:
        for _ in range(10):
            try:
                os.remove(p)
                break
            except FileNotFoundError:
                break
            except PermissionError:
                time.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())
