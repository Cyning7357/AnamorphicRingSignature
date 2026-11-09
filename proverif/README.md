# ProVerif 模型：入网 / 密钥分发

两个文件：

- `enroll.pv` — 诚实场景；
- `enroll_compromised.pv` — 负对照：提取方密钥 `sk_X` 泄露。

运行（本机 ProVerif 2.05）：

```
proverif enroll.pv
proverif enroll_compromised.pv
```

## 建模了什么

- KEM 封装到提取方公钥 `pk_X`，共享秘密只有持 `sk_X` 的一方能算；
- `dk_i = KDF(ss, oid || ep || i || pk_i)`，上下文绑定；
- 组织对 epoch 根签名，提取方验证签名后才派生 `dk_i`；
- 载荷用 `FPE(dk_i, r, μ)` 嵌入；
- **平台持有全部 agent 的 `sk`**（`out(c, skA)`），并看到所有公开值。

## 结果

| 查询 | 诚实 | 提取方泄露 |
|---|---|---|
| `attacker(payload)`（载荷保密） | **true（保密）** | false（被攻破） |
| `ExtractorRead(rt) ==> OrgApproved(rt)`（只接受组织签名的根） | **true** | true |

负对照说明边界是**提取方密钥**：平台拿到所有 `sk` 也读不出载荷；一旦 `sk_X` 泄露，载荷立刻失守——
这和论文里"`dk`/`td` 是单点"的表述一致。

## 不能由这个模型说明的

- **计算不可区分性**（拟态性）：ProVerif 是符号模型，不建模 PRP、LWE、概率；
- **环签名的匿名性**：那是计算性质，符号模型里无法表达"签名者不可区分"；
- **伪造成功概率**：模型只回答"能不能构造"，不回答"以多大概率"。

所以论文里应当写成：ProVerif 覆盖**入网协议的保密性与认证**，不覆盖拟态性与环匿名。
