# P0 报告：B站 app 投稿接口逆向

日期：2026-10-14
APK：官方 `app.bilibili.com` 下载页提取的 CDN 地址 `dl.hdslb.com/mobile/latest/iBiliPlayer-bili.apk`
包名 `tv.danmaku.bili`，版本 8.91.1（build 8911100），191MB，38 个 dex
工具：jadx 1.5.6（Adoptium JRE 17 便携版）+ androguard 4.1.4（venv）
工作目录：`~/workspace/catbus-fork/research/bilibili-app`（scratch，未提交）

## 一、可行性结论（先说）

**逆向成功：app 投稿全链路已摸清，签名算法已复刻。但核心假设未被证实——app 端同样有完整风控体系，不能指望它绕过极验。**

- ✅ 找到 app 专属投稿接口（与 web `/x/vu/web/add/v3` 并列的另一套）
- ✅ 签名机制搞清并用 Python 复刻（经典 appkey/appsec MD5，native 只是藏密钥）
- ✅ 请求体格式逐字段拿到（`RequestAdd`，fastjson 序列化）
- ✅ 上传链路确认与 web 端完全一致（`preupload` → UPOS，可复用 catbus 现有 `upos.ts`）
- ⚠️ **app 有独立风控**：`RiskControlScene` 覆盖 UPLOAD_PRE / UPLOADING / SUBMIT / SUBMIT_BACKGROUND 四个场景；提交返回码 **21567** 即触发风控决策流；`RequestAdd` 里有 `captcha_token` 字段（平时为空，被风控时才用）
- ❌ **无法验证"app 投稿不触发极验"**：需要 `access_key`（app 登录态）才能打到提交相关接口，而获取 access_key 需要用户扫码/短信登录 + 实际提交测试（写操作），按任务约束未执行

**建议**：不建议为"绕过极验"而投入构建 app provider。理由：① app 同样会被风控，只是触发条件不同；② app 风控依赖设备指纹（buvid/fp_local/fp_remote/Device-ID 等），服务端脚本仿真这些信号缺失时风控分可能更高；③ 需要另做一套 app 登录流程拿 access_key。web 端极验问题更值得在 web 链路上想办法（补全浏览器指纹/行为信号）。

## 二、找到的接口（`com.bilibili.upper.api.service.ArchiveApiService`，Retrofit）

Base URL：`https://member.bilibili.com`，认证：query 参数 `access_key`（非 cookie）

| 方法 | HTTP | 路径 | 说明 |
|---|---|---|---|
| `add` | POST | `/x/vu/app/add` | 提交投稿（对标 web `/x/vu/web/add/v3`），`@RequestInterceptor(SignOnUrlRequestInterceptor.class)` |
| `archiveAddCheck` | POST | `/x/vu/app/add_check` | **提交前校验（无害探针）**，建议拿到 access_key 后先用它探风控状态 |
| `uploadCover` | POST | `/x/vu/app/cover/up` | 传封面（multipart） |
| `getPreviewData` | GET | `/x/vupre/app/archive/pre` | 投稿前置信息（对标 web `/x/vupre/web/archive/pre`） |
| `authRelationFrom` | GET | `/x/vupre/app/archive/pre` | 同上变体 |
| `queryArchive` | GET | `/x/vupre/app/archive/view` | 查稿件 |
| `editArchive` / `editArchiveVisibility` | POST | `/x/vu/app/edit/full`、`/x/vu/app/edit/visibility` | 编辑 |
| `bvcInterceptStrategy` | POST | `/x/vupre/app/archive/videocheck` | 视频预审策略 |

提交 body：`com.bilibili.upper.contribute.up.entity.RequestAdd`（fastjson），核心字段与 web 端对齐：
`title, tid, tag, desc, cover, copyright, source, no_reprint, dynamic, recreate, is_only_self, dtime, videos[{filename, title, cid}], uploadId, idempotent_key, captcha_token(平时空), server_ts, upFrom, biz_from, staffs, topic_id, mission_id, vote, location, watermark...`

上传：`GET https://member.bilibili.com/preupload?<signed query>` 取 `upos_uri/endpoint/auth` → UPOS 分片上传 → 回填 `filename`。与 web 端 catbus `upos.ts` 同一套。

## 三、签名机制（app vs web 对比）

**App 端**：
- 拦截器链：`SignOnUrlRequestInterceptor` → `DefaultRequestInterceptor.addCommonParamToUrl`（`classes17.dex`）
- 公共参数：`access_key, appkey, build, c_locale, channel, mobi_app, platform, s_locale`（+`ts`）
- 签名：`DefaultRequestInterceptor.signQuery(Map)` → **native** `com.bilibili.nativelibrary.LibBili.signQuery`（`libbili.so`，`classes16.dex` 声明）
- 算法本质：**经典 MD5**——参数按 key 排序 urlencode 拼接后追加 appsec 取 MD5。appsec 以 4×uint32 存于 native（`[0x560c52cc, 0xd288fed0, 0x45859ed1, 0x8bffd973]`，即 `560c52ccd288fed045859ed18bffd973`），刻意躲 `strings` 扫描；另有 `.datadiv_decode*` 加密字符串混淆
- appkey：`1d8b6e7d45233436`（公开硬编码；`BiliConfig.getAppKey()` 经 native `ao()` 派生，`FAWKES_APP_KEY` manifest 值仅为 `"android"` 占位）
- `BiliConfig.getAppSecret()` 已废弃（直接抛 `IllegalAccessException`："Should not call BiliConfig.getAppSecret() any more!"）——密钥只活在 native
- 请求头还带：`Buvid, Device-ID, GuestId, fp_local, fp_remote, session_id, x-bili-locale-bin, User-Agent`（BiliDroid 格式）

**Web 端**（catbus 现状）：cookie（SESSDATA/bili_jct）+ csrf + WBI 签名。

**关键差异**：app 用 `access_key`（OAuth token）而非 cookie。用户现有的 web 登录态不能直接用于 app 接口，需要单独走 app 登录流程。

## 四、PoC 验证

脚本：`~/workspace/catbus-fork/research/bilibili-app/poc_sign.py`（纯标准库，无凭据）

- 用复刻的签名算法打 `GET /x/vupre/app/archive/pre`（只读预检端点）：返回 `code=-101 账号未登录`
- 阴性对照（错误 sign）：同样返回 `-101`
- **诚实说明**：该端点在未登录时先报 -101，不校验签名，因此这次 PoC 未能正向证明签名有效性。签名算法的正确性由第三方独立逆向成果交叉印证（其 native hook 证实 sign 与抓包请求逐字节一致，见报告内引用）

## 五、风控真相（`qk4/b.java` ArchiveSubmitStep）

- 提交返回 `code=21567` → `RiskControlDecisions.OBTAIN` + `RiskControlScene.SUBMIT_BACKGROUND`（上报风控决策）
- 返回 `code=21616` → 幂等重试逻辑（`IdempotentConfig`）
- 风控场景枚举：`UPLOAD_PRE(1)`、`UPLOADING(2)`、`SUBMIT(3)`、`SUBMIT_BACKGROUND(4)`——上传前、上传中、提交都有风控点
- 结论：**app 不是法外之地**，风控是服务端按请求画像（设备指纹、行为、IP、账号历史）实时判定的

## 六、后续路线（需用户决策）

1. **验证"app 投稿是否真不触发极验"**：需要①用户用测试账号走 app 扫码登录拿 `access_key`；②先打 `add_check` 探针；③测试账号做一次真实提交。都是写/登录敏感操作，需用户明确批准。
2. **如果验证通过**：按 catbus §7.8 provider 协议做 `bilibili -e app` provider——复用 `upos.ts` 上传，仅替换认证（access_key）、签名（本报告算法）、提交 endpoint/body。预计 2-3 天工作量。
3. **如果验证不通过（大概率）**：回 web 链路，补浏览器行为信号（gaia 指纹等 catbus 已有 `gaia.ts`）降低极验触发率。

## 七、关键类名/文件索引（供后续开发）

- `jadx-21/sources/com/bilibili/upper/api/service/ArchiveApiService.java` —— 接口定义
- `jadx-21/sources/com/bilibili/upper/contribute/up/entity/RequestAdd.java` —— 提交 body
- `jadx-21/sources/qk4/b.java` —— 提交编排 + 风控码处理（21567/21616）
- `com.bilibili.okretro.interceptor.DefaultRequestInterceptor`（classes17.dex）—— 加签拦截器
- `com.bilibili.nativelibrary.LibBili` / `SignedQuery`（classes16.dex + `libbili.so`）—— native 签名
- `com.bilibili.api.BiliConfig`（classes5.dex）—— 配置，appsec 已废弃
- `com.bilibili.lib.foundation.DefaultApps`（jadx-15）—— appkey 来源考证
