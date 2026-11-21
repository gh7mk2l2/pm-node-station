# PM 节点公益站（PM Node Station）

免费公开的节点订阅站：LinuxDo OAuth 登录后获得个人订阅链接（Clash / sing-box / Base64），节点批次由上游订阅自动同步 + 福利代理池补充，全部免费，无任何付费功能。

后端 Rust（axum + sqlx + PostgreSQL），前端为 Rust 后端直接托管的静态文件（深浅双主题，PM-Plan 同款设计语言）。

> 功能模型参考 Beicho/arkadia-sub（只参考功能设计，代码全部原创实现，未复制其代码）。

## 目录结构

- `src/` — Rust 后端源码
- `migrations/0001_init.sql` — 数据库迁移（users / sessions / oauth_states / node_batches / announcements / socks_pool / audit_logs / settings / sub_pulls / node_latency）
- `web/` — 前端（`index.html` + `static/app.js` + `static/styles.css`）
- `reference/arkadia-sub/` — 参考项目（只读，不参与构建）
- `reference/pmplan-web/` — PM-Plan 前端源码（设计基准，只读）
- `build.sh` / `.env.example` — 构建脚本与配置模板

## 部署（机器：InstaBox，/data/pm-node-station/ 开发，/data/pm-node-station-prod/ 生产）

```bash
# 1. 建库（PostgreSQL 17）
sudo -n -u postgres psql -c "CREATE USER pmnodes WITH PASSWORD '强密码';"
sudo -n -u postgres psql -c "CREATE DATABASE pmnodes OWNER pmnodes;"

# 2. 构建（共享 PM-Plan 的 cargo 缓存）
bash /data/pm-node-station/build.sh

# 3. 部署到生产目录并启动
sudo -n systemctl restart pm-node-station
curl -s http://127.0.0.1:8882/api/health
```

systemd 服务 `pm-node-station`：`WorkingDirectory=/data/pm-node-station-prod`，`EnvironmentFile=/data/pm-node-station-prod/.env`，`ExecStart=/data/pm-node-station-prod/bin/pm-node-station`，端口 8882。

## 配置

见 `.env.example`。必填：`DATABASE_URL`、`APP_URL`。OAuth 未配置时服务仍可启动，登录入口返回 503 并提示站长配置。

**OAuth 回调**：`{APP_URL}/api/auth/callback`。在 LINUX DO Connect 新建应用（或给 PM-Plan 的应用追加一个回调地址），把 `LINUXDO_CLIENT_ID` / `LINUXDO_CLIENT_SECRET` 填进生产 `.env`。

**公网入口**：PM-Plan 通过 Cloudflare 命名隧道（`plan.pmcat.top` → 127.0.0.1:8881）对外。给本站加一条同隧道的 ingress（如 `nodes.pmcat.top` → 127.0.0.1:8882）并在 Cloudflare DNS 加 CNAME 到隧道域名即可。

## 功能清单

- **登录**：LinuxDo OAuth（PKCE S256、state 一次性消费、bind cookie），DB 会话 30 天；首位注册用户为 root，`ADMIN_USERNAMES` 为 admin；最低信任等级可配置；封禁用户无法登录且会话立即失效。
- **批次**：管理员手动创建（粘贴节点文本，支持 Raw URI / Base64 / Clash YAML 混合解析去重）；激活/停用在 advisory 锁 + 事务里原子完成，任意时刻最多一个激活批次。
- **上游同步**：后台配置上游地址（只存库，不回显）；Raw/Base64/Clash YAML 三种格式；去重后建新批次原子切换；每天上海时区两个持久化随机时段（07:00–10:00、14:00–23:00）自动同步，手动同步不占自动槽位；PostgreSQL advisory lock 防重复拉取；同步失败不影响当前批次；SSRF 防护（仅公网 IP、≤3 跳转、20 秒超时、16MB 上限）。
- **代理池**：批量粘贴导入 SOCKS5/HTTP(S) 代理（解析标签/地区/国家/风险分，高风险 ≥10 不入池）；真实握手 + 204 探测测速（单例后台任务，100 并发，8 秒超时，进度可查）；每批最多 60 个福利代理（30 原生/家宽优先 + 30 实测高速优先，/24 子网 ≤2、同国家 ≤8，带种子稳定轮换）。
- **订阅**：每用户独立 UUID token 链接，可一键轮换；Clash YAML / sing-box JSON / Base64 三种格式；内置分流规则（直连/代理分流、广告拦截）；token 错误返回 404；订阅限流 30 次/分钟/IP；拉取记 `sub_pulls`。
- **延迟与状态**：节点延迟为真实 TCP 建连计时（32 并发，5 秒超时）；状态来自实测；用户可手动重新测速（每人 5 分钟一次）。
- **用户管理**：分页检索、封禁/解封（封禁即踢会话）、角色 user/admin/root（root 唯一、admin 不能提拔、只有 root 能改角色）。
- **公告 / 设置 / 审计 / 限流**：公告 CRUD 与展示开关；信任等级、路由模式（rules/global）、管理员用户名；全部管理员操作记审计日志；订阅与登录限流。

## 测试

```bash
cargo test --release   # 订阅生成、Clash/sing-box 解析、上游解析、批次切换、守卫、限流等单测
```

## 绝对禁止模拟

全站无任何假数据：没有数据时显示空状态；所有数字来自数据库或真实测量；无假登录开关；无硬编码节点。
