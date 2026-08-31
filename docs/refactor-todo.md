# WebUI 与 PDU 引擎重构 TODO

## 目标

- 将 `src/alice-sms-pusher.c` 重命名为 `src/webui.c`，作为 WebUI、配置、自启动、服务启停、HTTP 路由和 CLI 入口核心。
- 将 `src/alice-pusher-bot.c` 作为 PDU/strace/推送引擎核心，不再包含 `main`。
- 保持输出名称：继续输出 `output/alice-pusher-bot` 和自解压的 `output/alice-pusher-bot.run`。

## TODO

- [x] 新增 `src/alice-pusher-bot.h`，定义 WebUI 调用引擎的公共接口。
- [x] 将 `src/alice-sms-pusher.c` 改名为 `src/webui.c`。
- [x] 从 `webui.c` 删除重复的 PDU、strace、TLS webhook 发送实现。
- [x] 将 WebUI 当前已有的平台能力迁移到 `alice-pusher-bot.c` 引擎核心：
  - `dingtalk`
  - `feishu`
  - `wecom`
  - `bark`
  - `serverchan`
  - `discord`
  - `telegram`
  - `custom`
- [x] 在引擎核心保留目标进程选择能力：
  - `/sbin/zte_mifi`
  - `/sbin/zte_ufi`
  - 自定义绝对路径
- [x] 让 `webui.c` 通过引擎 API 启动服务、停止服务、清理 strace 子进程、读取手机号和发送测试消息。
- [x] 更新 `make.sh`，同时编译 `src/webui.c` 与 `src/alice-pusher-bot.c`。
- [x] 更新文档中仍指向旧源码名或旧入口的说明。
- [x] 运行构建和基础检查。

## 兼容要求

- 保持现有命令兼容：
  - `alice-pusher-bot`（默认启动 WebUI 并自动安装或升级持久化入口）
  - `alice-pusher-bot -w`
  - `alice-pusher-bot --webui`
  - `alice-pusher-bot --mode=service_start ...`
  - `alice-pusher-bot --mode=send_once ...`
- 保持现有配置文件格式兼容：`/mnt/userdata/etc_rw/alice_pusher.conf`。
- 不改变输出二进制名称。
- 持久化入口使用 NV 优先、`/etc/rc` 回退策略：
  - payload 和 NV wrapper 固定保存在 `/mnt/userdata/alice_pusher/`。
  - NV 可用时将 `path_sh` 指向 `/mnt/userdata/alice_pusher`，wrapper 最后继续加载原厂 `/sbin/global.sh`。
  - NV 不可用或写入校验失败时，识别 `/etc/rc` 所在挂载点，临时重挂为可写并原子安装带标记的启动块，完成后恢复原挂载状态。
  - NV 和 `/etc/rc` 两种方式都不可用时直接失败；不检测、不依赖或复用 Alice Wonder，也不直接写 MTD。
  - 升级时只清理历史版本由 Pushbot 自己写入的 `alice_rescue/autostart/alice-pusher-bot.sh`。
- 安装前检查 userdata 空间；空间不足时拒绝安装。

## 测试项

- [x] `sh ./make.sh` 成功生成 `output/alice-pusher-bot` 和 `output/alice-pusher-bot.run`。
- [x] 链接阶段无重复符号，重点检查 `main`、`send_webhook_msg`、`decode_pdu`、`signal_handler`。
- [x] `output/alice-pusher-bot` 无参数时启动 WebUI，并自动安装或升级持久化入口。
- [x] `output/alice-pusher-bot --mode=send_once` 缺参数时显示 usage。
- [x] Webhook 与 SMTP 共用独立的 `libbearssl.so.0`，业务传输层保留在主程序中，未使用的 BearSSL 内部符号不对外导出。
- [x] `.run` 自带并提取私有 TLS 动态库，裸二进制通过 `LD_LIBRARY_PATH=output/lib` 运行。
- [x] TLS 仅启用 TLS 1.2、ECDHE-RSA/RSA 与 AES-128-GCM/CBC 最小 cipher suite，关闭 CA、主机名和有效期校验。
- [x] 本地测试覆盖普通 Webhook、Bark V2、SMTP STARTTLS、SMTP 隐式 TLS，以及 RSA/ECDHE-RSA 和 GCM/CBC 套件。
- [x] WebUI 的启动、停止、重启、测试发送路径都调用引擎 API。
- [x] 自启动安装优先使用 NV `path_sh`，不可用时回退 `/etc/rc`，并提供对应模式、payload、脚本和运行状态。
- [x] 持久化自启动入口同时拉起 WebUI 和短信监控服务，并避免重复启动。
- [x] 持久化入口拉起 WebUI 时跳过重复安装；WebUI 卸载后当前会话重启不会自动重装。
- [x] Pushbot 持久化安装空间不足时显示明确的需要空间与可用空间。
- [x] WebUI 检测到 userdata 空间不足时，将自启动状态显示为“设备不支持”并禁用安装。
- [x] WebUI 目标端口被占用时，在目标设备侧定位并终止监听进程后重试绑定。

> 说明：主程序动态依赖私有 TLS 库以及设备的 `libc.so.0`、`libpthread.so.0`、`libgcc_s.so.1`；`.run` 携带私有 TLS 库和短信采集 helper。

## 已确定方案

- 采用动态主程序加自带私有 TLS 库、短信采集 helper 的 `.run` 交付方案。
- 保留 WebUI 当前已有的全部推送平台和自定义模板能力。
- WebUI 与引擎在同一二进制内通过 C 函数接口协作，不引入新的进程间协议。
