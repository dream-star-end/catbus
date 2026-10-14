# P1 降级路线：H5 签名补淘宝/闲鱼读接口（2026-10-14）

## 背景
P1 主路线（千牛 .NET 逆向）已判停：千牛 PC 9.97.56N 是原生 Win32+Qt+CEF，零 .NET 程序集；x-sign 在阿里加固 SecurityGuardSDK.dll 内不可复刻。
降级路线：用公开的 H5 签名算法 `sign = MD5(_m_h5_tk & timestamp & appKey & data)` 补淘宝/闲鱼读接口。
本目录记录验证过的 API 名、请求格式与风控结论，供后续维护参考。

## 验证结论（2026-10-14 真实请求实测）

### ✅ 真实打通（匿名可用）
| 接口 | API 名 | 说明 |
|---|---|---|
| `xianyu feed list` | mtop.taobao.idlehome.home.webpc.feed v1.0 | 推荐流，20 条/页，pageNumber 分页；cardType 61801 为商品卡 |
| `taobao keyword suggest` | suggest.taobao.com/sug（公开 GET） | 搜索联想词，无需签名 |

### ⏳ 代码实现完备，待登录验证（匿名被 RGV587 风控）
| 接口 | API 名 | 请求格式来源 |
|---|---|---|
| `xianyu item search` | mtop.taobao.idlemtopsearch.pc.search v1.0 | goofish 搜索页 JS 精确还原（keyword/rowsPerPage/searchReqFromPage） |
| `taobao comment list` | mtop.taobao.rate.detaillist.get v6.0 | 淘宝 PC 搜索页 JS 精确还原（auctionNumId/pageNo/pageSize/rateType/searchImpr/orderType/rateSrc=pc_rate_list，needLogin=false） |
| `taobao user get me` | cookie 解析 | 从 cookie 的 unb/_nk_ 返回当前用户；无登录态时诚实报 AUTH_REQUIRED |

### ❌ 判停 / 未做
- `taobao item search` / `taobao item get`：mtop API 名未发现
- `taobao msg list` / `xianyu msg list`：两平台均无 HTTP 会话列表接口（IM 走 websocket）
- `xianyu user get` 查他人：mtop.idle.web.user.page.nav 需登录且响应 shape 未知
- 淘宝/闲鱼 live 全系：需登录
- `xianyu user items`：API 未发现

## 关键发现
1. **H5 签名无需 token 即可匿名调通**：闲鱼 feed 接口用游客 token（buildInitialCookies 拿到的）签名后返回 SUCCESS。
2. **RGV587 是匿名风控墙**：搜索类、评价类接口匿名一律被拦，登录态可解（用户无淘宝测试号，无法闭环验证）。
3. **闲鱼登录态 = 淘宝登录态**：闲鱼用淘宝账号体系，但当前两边均未登录。
4. **CLI 级 auth 门禁**：taobao/xianyu web 端 `guest: false`，所有命令（含 API 可匿名的）CLI 层都要求登录——这是平台现有策略，与 item get 等已实现命令一致，本次未改。

## 产出文件
- 实现：`src/platforms/{xianyu,taobao}/web/{api,normalize,commands}.ts`、`src/platforms/{xianyu,taobao}/index.ts`
- golden：`tests/golden/xianyu/feed_list.json`、`tests/golden/taobao/keyword_suggest.json`
- 测试：tests/xianyu.test.ts、tests/taobao.test.ts
- 矩阵：docs/capabilities.md
