# x-bytebench-signature 逆向分析研究


## 样本数据

- TikTok (com.zhiliaoapp.musically) v34.5.5
- API 路径: `/bytebench/api/sdk/device/strategy/meta`, `/bytebench/api/sdk/device/strategy/batch/v2`, `/bytebench/api/task/result`
- follow/watch/star 关注更多参数

---


## 最终结论

```
x-bytebench-signature = SHA256(request_body + secret_key)

secret_key = "00qzdilcy900ojjtxy674bozlqmt0yja"
access_key = "a5fafb0vf8ba061000qzbwg0irxc02afaf4"
bytebench_app_id = 1233
```

- **算法**: 纯 SHA-256（不是 HMAC）
- **输入**: request_body 原始字节 + secret_key UTF-8 编码字节，直接拼接
- **输出**: 64位小写hex字符串
- **验证**: 两个 HAR 文件共 24 个请求，全部匹配

---

## 分析流程

### Phase 1: 静态分析 (JADX)

#### 1.1 入口定位

通过 JADX 搜索 `ByteBench` 相关类，找到初始化入口：

```java
// com.ss.android.ugc.aweme.benchmark.BenchmarkInitRequest
private final void initStrategy() {
    EB1 eb1 = new EB1();
    eb1.LIZ = "a5fafb0vf8ba061000qzbwg0irxc02afaf4";   // access_key
    eb1.LIZIZ = "00qzdilcy900ojjtxy674bozlqmt0yja";     // secret_key
    eb1.LIZJ = 1233;                                      // bytebench_app_id
    interfaceC36014EAwLIZIZ.LJIIJ(new EB0(eb1));
}
```

#### 1.2 数据流追踪

```
BenchmarkInitRequest.initStrategy()
  → EB1(access_key, secret_key, app_id)
  → EB0(eb1)
  → ByteBenchStrategyPort.init(eb0)
    → ByteBenchBundle.setString("access_key", "a5fafb0v...")
    → ByteBenchBundle.setString("secret_key", "00qzdilcy9...")
    → native_init(bundle.getHandle())  // 进入 libbytebench.so
```

#### 1.3 网络层调用链

```
BXNetWorkController.execute(ByteBenchRequest)
  → D2X.LIZ(req, resp)
    → BytebenchAPI.doPost(path, params, headers, body)  // retrofit
    → OkHttp3SecurityFactorInterceptor.intercept()
      → InterfaceC31441CUz.onCallToAddSecurityFactor(url, headers)
      → 返回含 x-bytebench-signature 的 headers Map
```

#### 1.4 关键发现

- `ByteBenchRequest.mHeaders` 在进入 `D2X.LIZ()` 时已经包含签名 → 签名在 native 层计算
- `OkHttp3SecurityFactorInterceptor` 通过 `onCallToAddSecurityFactor` 注入安全头
- 签名计算完全在 `libbytebench.so` native 层完成

#### 1.5 .so 加载链

```java
// X.C36005EAn (原名 X.EAn)
public static void LIZ() {
    ArrayList arrayList = new ArrayList();
    arrayList.add("c++_shared");
    arrayList.add("bytemonitor");
    arrayList.add("worker");
    arrayList.add("bytebench");  // libbytebench.so
    C214768bY.LIZ(arrayList);
}
```

### Phase 2: 动态分析 (Frida)

#### 2.1 Java 层 Hook

Hook `BXNetWorkController.execute` 抓到完整请求：

```
URL: https://api-va.tiktokv.com/bytebench/api/sdk/device/strategy/meta?access_key=...
Method: POST
Body: {"extra_info":{"_rticket":"...","aid":"1233",...}}
Headers: {x-bytebench-signature=a5140cef8565a939c9a1b786e3d80ecb..., Content-Type=application/json}
```

#### 2.2 Java 层 Mac.doFinal 没有 bytebench 签名

Java Crypto API 只有 `slardar` 和 `appsflyersdk` 的 HMAC 调用，确认 bytebench 签名不走 Java 层。

#### 2.3 Native 层分析

`libbytebench.so` 关键导出：

| 符号 | 偏移 | 含义 |
|------|------|------|
| `bytebench::StrategySettings::getSecretKey()` | +0x57974 | 获取 secret_key |
| `bytebench::StrategySettings::Builder::setSecretKey(string)` | +0x44d48 | 设置 secret_key |
| `bytebench::ByteBench::init(shared_ptr<ByteBenchConfiguration>)` | +0x43F0C | 主初始化 |

**关键发现**: libbytebench.so 没有导入任何 HMAC/SHA/EVP 函数 — crypto 实现被静态链接/内联。

#### 2.4 内存扫描

在 .so 内存中找到字符串 `"x-bytebench-signature"` 位于偏移 `+0x88310`。

### Phase 3: 算法验证 (Python)

使用两个 HAR 抓包文件（24 个请求），穷举各种算法组合：

```python
# 验证代码
body = base64.b64decode(req["base64"])
expected = req["headers"]["x-bytebench-signature"]
computed = hashlib.sha256(body + secret_key.encode()).hexdigest()
assert computed == expected  # 24/24 MATCH
```

#### 测试过的算法（不匹配）

- `HMAC-SHA256(secret_key, body)` ❌
- `HMAC-SHA256(access_key, body)` ❌
- `SHA256(secret_key + body)` ❌ (顺序反了)
- `SHA256(body)` ❌
- `HMAC-SHA256(secret_key, sorted_query + body)` ❌
- `SHA256(canonical_json + secret_key)` ❌
- ... 几十种组合

#### 命中算法

```
SHA256(body + secret_key)  ✅ 24/24 全部匹配
```

---

## 关键类名映射 (JADX 重命名 → 运行时)

| JADX 名 | 运行时名 | 说明 |
|----------|----------|------|
| X.AbstractC34287Dch | X.Dch | ICronetAppProvider 实现 |
| X.C36001EAj | X.EAj | ByteBench 全局配置单例 |
| X.C36005EAn | X.EAn | .so 加载器 |
| X.InterfaceC31441CUz | X.CUz | 安全因子接口 |
| X.C33143CzL | X.CzL | URL 解析工具 |
| X.C35420Duy | X.Duy | OkHttp RealInterceptorChain |

---

## 遇到的坑


---

## 文件结构

```
x-bytebench-signature/
├── README.md                                    — 本文件 (完整分析报告)
├── signature_impl.py                            — 最终签名函数实现
├── bruteforce/                                  — 穷举算法尝试 (历史记录)
│   ├── _tmp_brute_bytebench_sig.py              — 第1轮: HMAC/SHA 基础组合
│   ├── _tmp_brute_bytebench_sig2.py             — 第2轮: extra_info/request fields 作 key
│   ├── _tmp_brute_bytebench_sig3.py             — 第3轮: 扩展 key 变体 (反转/hash/大小写)
│   ├── _tmp_brute_bytebench_sig4.py             — 第4轮: 双 HAR 文件 + canonical JSON
│   ├── _tmp_verify_bytebench_sig.py             — 早期验证脚本
│   └── _tmp_verify_secret.py                    — secret_key 验证 (13种 HMAC 组合)
├── frida_hooks/                                 — Frida hook 脚本
│   ├── frida_hook_bytebench_sig_v1.js           — v1: 早期 Mac/OkHttp/ByteBenchRequest hook
│   ├── hook_bb_minimal.js                       — 最终版: Java 层最小 hook (3个点)
│   ├── hook_bb_native_minimal.js                — 最终版: Native 层 hook (偏移方式)
│   ├── hook_bytebench_signature_full.js         — 完整版: Java 层 13 层全链路
│   └── hook_libbytebench_native_full.js         — 完整版: Native 层 crypto + JNI
└── verify/                                      — 验证脚本
    ├── verify_signature.py                      — HAR 数据验证 (24/24 MATCH)
    └── compute_signature.py                     — 签名计算完整示例
```

---

## 适用范围

- TikTok (com.zhiliaoapp.musically) v34.5.5
- ByteBench SDK 2.0.10-1
- API 路径: `/bytebench/api/sdk/device/strategy/meta`, `/bytebench/api/sdk/device/strategy/batch/v2`, `/bytebench/api/task/result`
- access_key 和 secret_key 硬编码在 APK 中，不同版本可能不同


---

## 免责声明

本项目仅用于技术研究与自建环境调试。请遵守 TikTok 服务条款与当地法律法规，勿用于未授权批量或滥用。
