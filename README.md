# Alice Pusher Bot

这是一个基于开源的个人学习与研究项目，旨在为开发者提供一个用于学习和实验的工具。请在使用前仔细阅读以下内容。

---

## 免责声明

**本项目仅供个人学习和研究使用，禁止用于任何商业或非法目的。**

- 开发者保留对本项目的最终解释权。
- 使用者在使用本项目时，必须严格遵守 **中华人民共和国（含台湾省）** 以及使用者所在地区的法律法规。禁止将本项目用于任何违反相关法律法规的活动。
- 使用者应自行承担因使用本项目所产生的任何风险和责任。开发者不对因使用本项目而导致的任何直接或间接损失承担责任。
- 开发者不对本项目所提供的服务或内容的准确性、完整性或适用性作出任何明示或暗示的保证。使用者应自行评估使用本项目的风险。
- 若使用者发现任何商家或第三方以本项目进行收费或从事其他商业行为，所产生的任何问题或后果与本项目及开发者无关。使用者应自行承担相关风险。
- 本项目已采用 **Apache License 2.0** 开源协议，详情见项目根目录下的 `LICENSE` 文件。

---

## 构建平台

本项目推荐在 Linux 上交叉编译，目标运行环境为 ARMv7/uClibc。构建需要：

- 可运行的 `arm-linux-gnueabi-gcc`（GCC 9 或更新版本）和 `readelf`
- 与设备 ABI 匹配的 Alice Buildroot 输出目录
- Python 3

---

## 编译步骤

1. 克隆项目到本地：
   ```bash
   git clone https://github.com/your-username/alice-pusher-bot-zxic.git
   ```

2. 进入项目目录并执行编译脚本：
   ```bash
   cd alice-pusher-bot-zxic
   sh ./make.sh
   ```

   如果当前目录旁边存在 `../alice-buildroot/output-target`，脚本会自动使用其中与目标设备匹配的 ARM/uClibc sysroot。也可以显式指定 Buildroot 输出目录：
   ```bash
   ALICE_BUILDROOT_OUTPUT=/path/to/alice-buildroot/output-target sh ./make.sh
   ```

   编译器前端和 SDK 编译器也可以分别覆盖：
   ```bash
   CC=/path/to/arm-linux-gnueabi-gcc \
   SDK_CC=/path/to/arm-buildroot-linux-uclibcgnueabi-gcc sh ./make.sh
   ```

3. 编译成功后生成主程序 `output/alice-pusher-bot`、独立 BearSSL 动态库
   `output/lib/libbearssl.so.0` 和自解压的
   `output/alice-pusher-bot.run`。直接运行裸主程序时需要指定库目录：
   ```bash
   LD_LIBRARY_PATH=output/lib output/alice-pusher-bot
   ```

---

## 源码结构

- `src/webui.c`：WebUI、配置、自启动、服务管理和 CLI 入口。
- `src/alice-pusher-bot.c`：PDU 解码、strace 跟踪、Webhook 和 SMTP 邮箱推送引擎核心。
- `src/bearssl_transport.c`：Webhook 与 SMTP 共用的 TCP/BearSSL 传输层。
- `src/alice-pusher-bot.h`：WebUI 调用引擎核心的公共接口。
- `third_party/bearssl`：构建独立 `libbearssl.so.0` 的 BearSSL 0.6 最小源码子集。
- `tests/test_pdu.c`：不连接网络的 PDU 解码与长短信拼合测试。
- `tests/run_tests.sh`：PDU、HTTPS、SMTP STARTTLS 和隐式 TLS 测试入口。

---

## 注意事项

- 请确保您的系统环境满足依赖要求。
- `.run` 会携带独立的 `libbearssl.so.0` 和面向目标 ARMv7/uClibc 环境的轻量 `sms-ptrace`。启动器自动设置动态库目录；目标系统只需提供已有的 `libc.so.0`、`libpthread.so.0` 和 `libgcc_s.so.1`。TCP、Webhook 和 SMTP 传输代码保留在主程序中，BearSSL 库本身不包含业务接口。
- WebUI 支持最多 4 个推送目标；Webhook 和 SMTP 邮箱均可作为独立目标同时启用，每个目标使用独立的平台、地址和模板配置。邮箱支持明文、STARTTLS 和隐式 TLS。
- HTTPS/SMTP TLS 使用 BearSSL，固定为 TLS 1.2，支持 ECDHE-RSA 与 RSA 密钥交换以及 AES-128-GCM/CBC；Bark 可直接使用 `https://api.day.app/DEVICE_KEY`。为保持原有行为，当前不校验证书链、主机名和有效期，连接可能受到中间人攻击。
- WebUI 的“实验功能”页面默认启用长短信分段拼合，支持 UCS2、GSM 7-bit，以及 8 位和 16 位 UDH 引用号。分段支持乱序和重复到达，收齐后只推送一次。
- 长短信拼合限制为最多 16 段、拼合后最多 4096 字节，缓存超时时间为 120 秒。超时、超限或不支持的编码只记录并丢弃，不发送不完整短信；关闭开关后恢复每个 PDU 独立推送。
- 配置文件中的 `long_sms_reassembly=1` 或 `0` 控制该功能。通过 WebUI 保存时，如果短信监控服务正在运行，会自动重启服务使设置立即生效。
- 项目仅用于技术交流，请勿用于任何违法用途。

---

## 赞助支持

如果您喜欢这个项目并希望支持开发者持续维护和更新，欢迎通过以下链接了解赞助方式：

> ![1](https://github.com/user-attachments/assets/1fcd4665-efd8-4f0e-a0d4-506e991b7b2f)

---
