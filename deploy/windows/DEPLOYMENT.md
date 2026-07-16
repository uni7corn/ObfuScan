# ObfuScan Windows VPS 小规模安全上线指南

## 先明确：Codex 不是服务器托管商

Codex 可以在当前工作区分析、修改和生成部署文件，但**不会因为打开一个 Codex 任务就自动分配一台长期在线的服务器、固定公网 IP、域名、带宽或防攻击额度**。`127.0.0.1:8080` 是当前电脑上的本地进程；进程退出、电脑关机或 Codex 任务环境结束后，网页就会断开。

上线前需要由你提供并付费维护：

- 一台 Windows VPS（建议 Windows Server 2022 或更新版本）；
- 一个域名及其 DNS 控制权；
- VPS 公网 IP、云防火墙和备份；
- Caddy、Python 与运行库的可信安装来源；
- 后续补丁、日志、监控和事故响应。

本目录只生成可审计的配置示例，**不会下载安装软件，不会修改 Windows 服务、防火墙、注册表或 DNS**。

## 推荐拓扑与配置

```text
Internet
   |
   | HTTPS :443（可选 :80，仅用于证书签发和跳转）
   v
Caddy：TLS + Basic Auth + 512 MiB 上限 + 安全响应头
   |
   | 仅本机 127.0.0.1:8080
   v
Python web_server.py：并发连接 8 / 并发扫描 1
   |
   v
ObfuScan.exe
```

个人或小团队使用建议从 **4 vCPU、8 GiB RAM、80 GiB SSD/NVMe** 起步。2 vCPU / 4 GiB 只适合受控测试，不建议匿名公网服务。265 MiB APK 会同时消耗上传临时空间、扫描 CPU 和日志空间；至少保留 4 GiB 空闲磁盘，本示例在空间不足时拒绝上传。

## 文件说明

- `obfuscan.config.example.psd1`：后端环境参数示例；复制后才使用。
- `Start-ObfuScan.ps1`：校验配置，隐藏启动后端并执行 `/status` 健康检查。
- `Stop-ObfuScan.ps1`：核对 PID 与命令行后停止后端，避免误杀其他进程。
- `caddy.env.example.ps1`：域名、ACME 邮箱和 Basic Auth 参数示例。
- `Caddyfile.example`：Caddy HTTPS 反向代理模板。

`obfuscan.config.psd1`、`caddy.env.ps1`、运行状态和日志均已写入本目录 `.gitignore`，不要把实际凭据提交到仓库。

## 1. 准备 VPS（人工操作）

1. 使用普通、非管理员 Windows 账户运行扫描进程；不要用 LocalSystem 或域管理员账户。
2. 将项目放到固定目录，例如 `D:\Tools\ObfuScan`，确认新版 `ObfuScan.exe`、`web_server.py` 和 `LibChecker-Rules` 都在。
3. 从官方可信来源安装 64 位 Python 3.11/3.12 与 **Caddy 2.10.0 或更高版本**，并记录绝对路径。本部署包不代为下载。模板使用了 Caddy 2.10 起提供的 `request_body max_size`。
4. DNS 中将域名（例如 `scan.example.com`）的 A/AAAA 记录指向 VPS。
5. 云防火墙只放行 TCP 443；若 Caddy 使用 HTTP-01 或需要 HTTP 跳转，再放行 TCP 80。**绝不放行 TCP 8080、2019 或 RDP 给全网。** RDP 最好经 VPN/堡垒机或固定管理 IP 访问。

后端绑定和云防火墙是两层独立防线：即使误配了其中一层，另一层仍应阻止公网直接访问 8080。

## 2. 配置并启动环回后端

在管理员完成目录权限后，切换到专用的普通运行账户执行：

```powershell
Set-Location D:\Tools\ObfuScan\deploy\windows
Copy-Item .\obfuscan.config.example.psd1 .\obfuscan.config.psd1
notepad .\obfuscan.config.psd1
```

至少核对 `ProjectRoot`、`PythonExecutable` 和 `EngineExecutable`。默认配置如下：

- 仅监听 `127.0.0.1:8080`；启动器拒绝任何非环回地址；
- 最大请求 `536870912` 字节（512 MiB），足够上传已验证的 265 MiB APK及 multipart 开销；
- 同时只允许 1 个扫描、8 个活动连接；
- 扫描器 stdout/stderr 分别限制为 32 MiB / 1 MiB，避免异常输出吃光 Web 进程内存；
- 扫描超时 15 分钟，客户端空闲超时 60 秒；
- 至少预留 4 GiB 磁盘；
- 公网响应不泄露引擎绝对路径。

启动并验证：

```powershell
.\Start-ObfuScan.ps1
Invoke-RestMethod http://127.0.0.1:8080/status
Get-NetTCPConnection -LocalPort 8080 -State Listen
```

`LocalAddress` 必须是 `127.0.0.1`，不能是 `0.0.0.0`。日志位于 `logs\web.stdout.log` 和 `logs\web.stderr.log`。

停止：

```powershell
.\Stop-ObfuScan.ps1
```

隐藏启动不等于系统服务，也不保证重启后自动恢复。待人工验证稳定后，可由管理员选择 Windows 服务包装方式；这属于系统变更，不在本部署包内自动执行。

## 3. 配置 HTTPS、域名和鉴权

先复制环境与 Caddy 配置：

```powershell
Set-Location D:\Tools\ObfuScan\deploy\windows
Copy-Item .\caddy.env.example.ps1 .\caddy.env.ps1
Copy-Item .\Caddyfile.example .\Caddyfile
notepad .\caddy.env.ps1
```

先用密码管理器生成至少 20 位随机口令，再让 Caddy 在终端中交互式读取（输入不会出现在命令历史或进程参数中），只保存生成的 bcrypt 哈希：

```powershell
. .\caddy.env.ps1
$env:OBFUSCAN_BASIC_AUTH_HASH = & C:\Caddy\caddy.exe hash-password
```

若需要跨会话启动 Caddy，将新哈希填入被 `.gitignore` 排除的 `caddy.env.ps1`，然后在同一 PowerShell 会话中执行静态校验和前台试运行：

```powershell
. .\caddy.env.ps1
& C:\Caddy\caddy.exe validate --config .\Caddyfile --adapter caddyfile
& C:\Caddy\caddy.exe run --config .\Caddyfile --adapter caddyfile
```

先保持 Caddy 前台运行，访问 `https://你的域名/status` 和页面，确认浏览器证书有效、会弹出 Basic Auth、265 MiB 测试 APK 能完成上传，再考虑由管理员配置自启动。

注意：Caddy 与后端均使用 512 MiB 请求上限。若接入 CDN/WAF，必须核对该服务套餐的单请求上传上限与源站超时；上游若小于 265 MiB，上传仍会失败。

## 4. 攻击面与防护边界

APK 是攻击者可控的复杂二进制输入。即使当前代码限制了大小、连接数、扫描并发、超时和磁盘预留，也不能把它视为可以安全匿名开放的普通静态网站。

最低上线要求：

- **禁止匿名访问**：保留 Basic Auth，口令使用密码管理器生成并定期轮换；离职或泄露时立即轮换。
- **单扫描并发**：保持 `MaxConcurrentScans = 1`，防止 CPU、内存、磁盘被并行任务耗尽。
- **网络隔离**：8080 与 Caddy 管理端口 2019 仅环回；公网只到 443/必要时 80。
- **低权限隔离**：扫描账户不是管理员，对系统目录无写权限；最好让这台 VPS 只承担 ObfuScan，不与生产数据库、源码密钥或内网 VPN 混用。
- **出站限制**：扫描本身不需要主动访问互联网时，可由管理员在验证证书续期与系统更新路径后，对扫描进程实施出站限制。
- **补丁与杀毒**：及时更新 Windows、Python、Caddy 和编译运行库，开启 Defender/EDR；不要把上传临时目录加入全局排除。
- **日志与容量告警**：监控 CPU、内存、磁盘、进程存活、HTTP 401/413/429/5xx 和异常上传频率；Caddy JSON 日志默认滚动保存。
- **上游抗 DDoS**：VPS 本机配置无法抵挡大流量 DDoS。需要云厂商清洗/WAF/带宽防护；启用前确认其支持至少 512 MiB 请求和 20 分钟源站等待。

本 Caddy 模板提供鉴权、请求体上限和后端并发边界，但**标准 Caddy 不等于完整的按 IP 速率限制或 DDoS 清洗系统**。若要多人开放，优先在云 WAF/API 网关配置每账号/IP 配额；不要随意安装来源不明的 Caddy 限流插件。

## 5. 被攻击或疑似入侵时

按以下顺序止损：

1. 在云防火墙临时关闭 443/80，或将 DNS 切到维护页；不要只停止 Python 后端。
2. 保存 Caddy 日志、Windows 事件日志、Defender/EDR 告警、进程列表和文件哈希；不要先清日志。
3. 停止 ObfuScan，轮换 Basic Auth、VPS 管理凭据以及同机存在的其他密钥。
4. 对 `ObfuScan.exe`、`web_server.py`、Caddy 配置和部署包与可信发布件做哈希比对。
5. 若确认代码执行或管理员权限失陷，不要在原系统上“清干净后继续用”；从干净镜像重建 VPS，恢复经过验证的程序与配置。
6. 完成根因分析、修复和小流量复测后再重新开放。

## 6. 上线验收清单

- [ ] Codex 没有被当作 VPS/托管服务；VPS、域名、DNS 和费用归属已明确。
- [ ] `ObfuScan.exe` 与计划发布版本哈希一致。
- [ ] 后端只监听 `127.0.0.1:8080`，公网扫描确认 8080/2019 不可达。
- [ ] HTTPS 证书有效，HTTP 自动跳转 HTTPS。
- [ ] 未认证访问返回 401，强口令认证后才能上传。
- [ ] 超过 512 MiB 的请求在 Caddy 层被拒绝。
- [ ] 265 MiB 基准 APK 能在 20 分钟代理超时内完成扫描。
- [ ] 同时提交多个任务时，最多只有 1 个进入扫描，其余被明确拒绝/等待而非拖垮主机。
- [ ] 日志滚动、磁盘余量、进程健康和异常状态已接入监控。
- [ ] 已演练关闭公网入口、轮换口令和从干净镜像恢复。
