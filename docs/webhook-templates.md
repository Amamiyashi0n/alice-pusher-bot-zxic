# Webhook 模板

Alice Pusher Bot 目前按“纯文本消息”发送，WebUI 里选择平台后会自动生成对应请求体。

## 钉钉

Webhook URL 通常形如：

```text
https://oapi.dingtalk.com/robot/send?access_token=...
```

发送格式：

```json
{"msgtype":"text","text":{"content":"短信内容"}}
```

## 飞书

Webhook URL 通常形如：

```text
https://open.feishu.cn/open-apis/bot/v2/hook/...
```

发送格式：

```json
{"msg_type":"text","content":{"text":"短信内容"}}
```

## 企业微信

Webhook URL 通常形如：

```text
https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...
```

发送格式：

```json
{"msgtype":"text","text":{"content":"短信内容"}}
```

## Server 酱

Webhook URL 通常形如：

```text
https://sctapi.ftqq.com/SENDKEY.send
```

发送格式：

```text
title=Alice%20Pusher&desp=短信内容
```

## Discord

Webhook URL 通常形如：

```text
https://discord.com/api/webhooks/...
```

发送格式：

```json
{"content":"短信内容"}
```

## Telegram Bot

Webhook URL 需要把 `chat_id` 放进 URL：

```text
https://api.telegram.org/botTOKEN/sendMessage?chat_id=CHAT_ID
```

发送格式：

```text
text=短信内容
```

## Bark

Webhook URL 通常形如：

```text
https://api.day.app/DEVICE_KEY
```

程序会从 URL 中提取 `DEVICE_KEY`，实际使用 Bark V2 JSON 推送：

```json
{"title":"Alice Pusher","body":"短信内容","device_key":"DEVICE_KEY"}
```

## 自定义

选择“自定义”后，可以自行填写 `Content-Type` 和完整消息体模板。

常用 JSON 示例：

```json
{"text":"{{json_text}}"}
```

常用表单示例：

```text
title=Alice&desp={{url_text}}
```

可用占位符：

- `{{json_text}}`：短信内容经过 JSON 字符串转义，适合放在 JSON 字符串值里。
- `{{url_text}}`：短信内容经过 URL/form 编码，适合 `application/x-www-form-urlencoded`。
- `{{text}}`：短信原文，不额外转义。

## 说明

- 如果配置文件里没有 `platform=`，程序会根据 URL 域名自动猜测平台。
- 如果平台使用签名、关键字、IP 白名单等安全策略，需要在对应平台后台自行配置。
- 内置平台使用 text 推送模板；特殊平台可以用“自定义”自行构造请求体。

## 邮箱推送目标

WebUI 将邮箱作为目标列表中的一种推送类型，最多可与其他 Webhook 或邮箱目标同时启用。每个邮箱目标独立填写 SMTP 服务器、发件人和收件人；用户名和密码按邮件服务商要求填写。

安全模式支持：

- `STARTTLS`：通常使用 587 端口，推荐。
- `隐式 TLS`：通常使用 465 端口。
- `明文`：通常使用 25 端口，仅适合可信内网 SMTP。

当前版本不校验证书，SMTP 账号配置保存于 `/mnt/userdata/etc_rw/alice_pusher.conf`，文件权限为 `0600`。每条短信会发送到所有已启用且配置完整的目标；某个目标失败时仍会继续发送其他目标，并在运行日志中标出失败目标。

旧版本的单 Webhook 或单邮箱配置会在读取时自动迁移；如果旧配置同时存在两类目标，会迁移为两个独立目标。
