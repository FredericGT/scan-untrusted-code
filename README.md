# scan-untrusted-code

一个面向 Codex 的未知代码安全检查 Skill，用于在运行陌生仓库、脚本、压缩包或依赖之前，进行静态、只读的安全评估。

它的设计目标是把“先检查、再运行”固化成可复用的安全门禁，重点覆盖本次 macOS Node/Git Hook 事件中暴露的风险。

## 核心能力

- 静态扫描目录、单文件、ZIP、TAR、TGZ、TAR.GZ、TAR.BZ2 和 TAR.XZ
- 检查 Git Hook、`.git/config`、npm 生命周期脚本和常见自动执行入口
- 识别远程下载、Pipe-to-Shell、Node/Shell/Python 执行和动态代码执行
- 检查浏览器数据库、Keychain、SSH、AWS、Git、云凭证、钱包和剪贴板访问
- 识别临时目录、上传能力、清理行为、持久化和可疑文件链接
- 检测归档路径穿越、符号链接/硬链接和超大文件
- 默认加载本次事件的 `daam` Node Stealer IOC 包，也支持自定义 IOC
- 输出 Markdown 和 JSON 报告，并给出可解释的风险等级

## 安全边界

扫描器不会：

- 执行、安装、构建、测试或导入目标代码
- 运行目标仓库中的 `git`、`npm`、`pip`、`node`、`make` 等工具
- 解压归档后再扫描
- 自动提交登录凭证、MFA 或 OAuth 授权
- 自动上传私有样本到第三方信誉服务

如果需要动态验证，应使用没有企业凭证、默认断网、可销毁的一次性沙盒。

## 在 Codex 中使用

```text
使用 $scan-untrusted-code 扫描这个未知仓库，只做静态分析，不执行代码，并输出风险报告。
```

也可以指定目标：

```text
使用 $scan-untrusted-code 扫描 /Users/xxx/Downloads/unknown.zip，重点检查 Git Hook、安装脚本、Node 下载执行和凭证访问。
```

## 命令行使用

```bash
python3 ~/.codex/skills/scan-untrusted-code/scripts/scan_untrusted_code.py \
  /absolute/path/to/artifact \
  --format both \
  --output-dir /tmp/untrusted-code-report \
  --exit-zero
```

输出：

```text
/tmp/untrusted-code-report/scan-report.md
/tmp/untrusted-code-report/scan-report.json
```

使用自定义 IOC：

```bash
python3 ~/.codex/skills/scan-untrusted-code/scripts/scan_untrusted_code.py \
  /absolute/path/to/artifact \
  --ioc-pack /absolute/path/to/custom-iocs.json \
  --format both \
  --output-dir /tmp/untrusted-code-report \
  --exit-zero
```

## 风险等级

| Verdict | 含义 | 建议 |
|---|---|---|
| `low_indicators` | 当前规则未发现已知高风险特征 | 继续正常控制，不代表绝对安全 |
| `manual_review` | 存在中等或上下文相关指标 | 人工复核后再决定 |
| `sandbox_only` | 存在高风险能力或执行入口 | 不要在工作终端运行 |
| `block` | 命中可执行的 Critical 信号或明确恶意行为链 | 禁止运行并升级安全团队 |

V1.1 不再仅凭累计分数触发 `block`。文档、CI、Issue 模板、测试和 `.gitignore` 等上下文会被降权；阻断需要可执行的 Critical 信号、明确行为链、关键 IOC 或归档安全问题。

## 目录结构

```text
scan-untrusted-code/
├── SKILL.md
├── README.md
├── agents/
│   └── openai.yaml
├── references/
│   ├── checks.md
│   ├── ioc-pack-daam-node-stealer.json
│   ├── risk-model.md
│   └── sandbox-baseline.md
├── scripts/
│   └── scan_untrusted_code.py
└── tests/
    └── test_scan_untrusted_code.py
```

## 证据语言

报告会区分：

- `Confirmed`：静态内容中确实存在的文件、命令、路径或 IOC
- `High Confidence`：多个已确认能力组成的高置信行为链
- `Not Confirmed`：需要运行时证据才能确认的执行、上传、凭证使用或影响

扫描结果不会直接声称“数据已经泄露”或“仓库绝对安全”。

## 验证

运行回归测试：

```bash
python3 tests/test_scan_untrusted_code.py -v
```

验证 Skill 元数据：

```bash
python3 /Users/yuanjuntao/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
```

当前回归覆盖：

- 恶意 `post-checkout` Hook → 远程下载 → Node 执行链
- 浏览器/Keychain/钱包访问与网络能力组合
- ZIP 路径穿越
- npm 生命周期脚本
- 正常 CI、文档和 `.gitignore` 示例的误报抑制
- 超大文件限流

## 当前限制

V1.1 仍是离线静态扫描器，暂未自动完成：

- GitHub、npm、PyPI 仓库信誉查询
- 依赖漏洞解析
- Python/macOS `.so`、`.dylib` 签名和 provenance 检查
- YARA、反编译或动态执行
- 成功上传、凭证使用和实际影响确认

低风险结果只表示“当前规则未发现已知高风险指标”，不等于代码已经被证明安全。

## Repository

[FredericGT/scan-untrusted-code](https://github.com/FredericGT/scan-untrusted-code)
