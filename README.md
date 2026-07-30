# RTools Marketplace

v0.8 提供插件上传、服务端安全扫描、审核、发布、市场签名、搜索、下载、评分、举报、管理后台和市场身份元数据。协议验证复用 `../RToolsPluginSDK/schemas`，市场兼容协议见 `../RToolsPluginSDK/docs/MARKETPLACE_PROTOCOL_V1.md`。

```bash
npm install
npm test
npm start
```

运行 `docker compose up -d` 启动 API、MySQL 8 和 MinIO。管理后台为 `http://127.0.0.1:8787/admin`，MinIO 控制台为 `http://127.0.0.1:9001`。

本地管理后台默认账号为 `admin` / `admin888888`。Compose 中的密码只适用于本地开发，部署时必须由密钥管理服务覆盖。

```bash
npm run migrate
powershell -File scripts/backup.ps1
```

SDK 发布需要 `RTOOLS_MARKETPLACE_URL` 与 `RTOOLS_MARKETPLACE_TOKEN`。`rtools publish` 会上传真实 `.rtools` 二进制包，服务端重新计算哈希、验证 ZIP 文件清单和开发者签名，然后进入审核队列。

## 市场身份

本项目可以作为 RTools 官方市场的服务端，也可以作为用户自建市场的参考实现。客户端会通过以下接口识别市场来源：

```text
GET /api/v1/market/metadata
GET /api/v1/market/public-keys
GET /api/v1/revocations
```

关键环境变量：

```bash
RTOOLS_MARKET_ID=official.rtools.app
RTOOLS_MARKET_KEY_ID=official.rtools.app-ed25519-2026
RTOOLS_MARKET_NAME="RTools Official Marketplace"
RTOOLS_MARKET_BASE_URL=https://market.rtools.app
MARKETPLACE_SIGNING_KEY=/run/secrets/rtools-market-ed25519.pem
```

自建市场必须改成自己控制的 `RTOOLS_MARKET_ID`，例如 `plugins.example.com`。开源本参考实现不包含 RTools 官方市场的线上部署、签名私钥、审核策略、商业结算、风控规则、运营数据或官方品牌授权。

RTools 正式客户端可以内置 `RTOOLS_OFFICIAL_MARKET_PUBLIC_KEY` 来固定官方市场公钥；因此自建市场即使复制 `official.rtools.app` 也不会获得官方身份。
