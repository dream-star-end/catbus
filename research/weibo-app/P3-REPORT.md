# P3 微博 app 写操作可行性探测报告

日期：2026-10-14
APK：微博 16.9.3（包名 com.sina.weibo，245,177,921 字节）
签名：Sina.Com Technology (China) Co. Ltd（证书 subject/issuer 已验证，官方包）
来源说明：weibo.com 官方应用页为 JS SPA，直接拉取失败；采用 APKPure 签名验证的官方构建（与官方证书一致）。

## 一、app 请求签名机制定位（精确到类/方法）

**结论先行：请求层没有客户端密码学签名。**

| 环节 | 类/方法 | 行为 |
|---|---|---|
| 接口门面 | `com.sina.weibo.net.l`（307 个内部接口，`dex/classes7.dex`） | 纯 URL 常量 + Bundle 组装 |
| 中央执行器 | `com.sina.weibo.net.o$a` → `com.sina.weibo.net.p` → `com.sina.weibo.utils.js.a(String, Bundle)` | 只做 query 参数拼接，无签名 |
| 编码 | `com.sina.weibo.net.httpmethod.HttpUtils.encodeUrl(Bundle)` | 纯 URL 编码 |
| 通用参数 | `com.sina.weibo.requestmodels.RequestParam.fillCommonParam(Bundle)` | 明文拼装：`gsid`, `c="android"`（字面量）, `s`, `from=10G9395010`, `wm=3333_1001`, `oldwm`, `ua`, `android_id`, `aid`, `tsid`, `ul_ctime` 等 |
| net 包内 crypto | `net/carrier/Strategy/c` (HmacSHA1)、`net/wns/b/a/h` (HmacSHA256) | 均为文件完整性校验，与请求签名无关 |
| native 库 | **APK 内零 .so 文件** | — |

**唯一的"签名"参数 `s`**：
- `s = SLib.newCalculateS(uid)`（`RequestParam.initUserParam` ← `jv.a(uid)`）
- `com.sina.weibo.security.SLib.newCalculateS` → **native** `nativeNewCalculateS`（`dex/classes17.dex`）
- `libslib.so` 不在 APK 内（lib/、assets/ 均无），运行时动态下发；加载失败时 `s=""`（`jv.a` 兜底返回空串）
- `WBSecurity.getSignature("weibo")` 校验 app 自身签名 —— 该 native 模块与官方应用签名绑定

**发博走服务端签名**：`/2/!/statuses/get_ssig_url`（`net/l.a(RequestParam)String`，`dex/classes7.dex`）返回 `result_data.ssig_url`，客户端无密码学参与。

**登录**（`/2/account/login`，`requestmodels/gu`，`dex/classes12.dex`）：`u`（用户名）+ `p`（密码，setter `m(String)` 直接写入字段 `b`，**明文传输、无客户端哈希**）+ `device_id/imei/android_id/uicode/luicode/fromuicode/mode`。

## 二、PoC 验证（无害端点、零真实凭据）

| PoC | 请求 | 结果 |
|---|---|---|
| PoC-1 | `GET /2/guest/login`（`s=""`，无 gsid） | HTTP 200，`errno:-100` 通用错误 —— 非签名拒绝 |
| PoC-2 | `GET /2/!/statuses/get_ssig_url`（未登录） | HTTP 200，`errno:-200` "校验参数不存在" —— **鉴权失败而非签名失败**，写操作是会话门控 + 服务端签名 |
| PoC-3 | `GET /2/account/login`（伪造账号） | HTTP 200，`errno:-2118`，直接返回 `passport.weibo.cn/verify/index` 人机验证 —— **未知设备第一次请求即触发风控** |

## 三、可行性结论：判死

1. **没有"签名算法"可破解**：请求认证 = `gsid` 会话参数，无客户端密码学。真正的墙是账号风控体系，不是签名。
2. **拿 app `gsid` 需要真实用户凭据**（密码/短信）+ 过设备验证；服务端对未知设备首请求即弹验证（errno -2118），与 web 端被 suda 风控挡死（6102/newlogin）同源。
3. **即使登录，写操作同样受风控**；且 `s` 参数依赖动态下发、官方签名绑定的 native 模块，服务端可随时收紧校验 —— 复刻它是持续军备竞赛。
4. **web 端 cookie 无法兑换 app `gsid`**，两条链路不互通；用户现有的微博登录态帮不上 app 端。

**建议**：P3 收口，不再投入。如用户未来提供测试账号凭据并明确接受风控风险，可重开验证，但预期仍会被风控拦截。

## 四、过程产物

- `research/weibo-app/weibo_latest.apk`（官方包，分析用）
- `research/weibo-app/dex/`（18 个 dex 解包）
- `research/weibo-app/scan1_strings.py`、`scan2_xref.py`（轻量分析脚本，androguard 单 dex 模式，避开全量 OOM）
- `research/weibo-app/api_paths.txt`（307 个内部接口路径全集）
- `research/weibo-app/poc_noauth.py`（无害 PoC）
- `research/weibo-app/venv/`（androguard 4.1.4）
