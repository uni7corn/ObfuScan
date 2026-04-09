# ObfuScan

[English](#english) | [中文](#中文)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/1998lixin/ObfuScan)](https://github.com/1998lixin/ObfuScan/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Language](https://img.shields.io/badge/language-C%2B%2B17%20%7C%20Python3-blue)]()

---

## 中文

一个面向 **Android APK Native SO 预筛选** 的小工具。  
核心目标不是"完整还原逻辑"，而是作为**逆向分析 / 安全审计前的前置探针**，帮助你在一堆 `arm64-v8a` 的 `.so` 里，**更快发现高价值目标**。

---

### 📑 目录

- [项目定位](#项目定位)
- [快速开始](#快速开始)
  - [方法一：Web 界面（推荐）](#方法一web-界面推荐)
  - [方法二：命令行](#方法二命令行)
- [从源码编译](#从源码编译)
- [工作原理（评分模型）](#工作原理评分模型)
- [当前支持的能力](#当前支持的能力)
- [输出结果怎么看](#输出结果怎么看)
- [关于准确率的说明](#关于准确率的说明)
- [一个典型使用思路](#一个典型使用思路)
- [当前已知局限](#当前已知局限)
- [后续可能的方向](#后续可能的方向)
- [适合谁使用](#适合谁使用)
- [贡献指南](#贡献指南)
- [许可证](#许可证)
- [致谢](#致谢)

---

### 项目定位

**ObfuScan 不是一个"全自动还原保护逻辑"的工具。**  
它更像一个**审计前的前哨站**：

- 帮你快速扫 APK 中所有 64 位 SO
- 给出简洁的中文风险摘要
- 按 **高 / 中 / 低** 风险排序
- 对高风险样本进一步展示关键入口预览
- 让你更快决定：
  - 哪几个 SO 值得先看
  - 哪些入口值得先下断点 / 先反汇编 / 先做动态跟踪

一句话总结：

> **先筛选，再深挖。**  
> 把有限的逆向时间优先花在更可能有价值的目标上。

---

### 快速开始

#### 方法一：Web 界面（推荐）

1. **启动 Web 服务器**

   ```bash
   cd ObfuScan
   python web_server.py
   ```

2. **访问 Web 界面**

   打开浏览器，访问 http://127.0.0.1:8080

3. **上传 APK 并分析**

   - 点击"选择APK文件"按钮，选择要分析的APK文件
   - 点击"开始分析"按钮
   - 等待分析完成后查看结果

#### 方法二：命令行

1. **运行 ObfuScan**

   ```bash
   ObfuScan.exe <apk_path>
   ```

2. **查看输出**

   命令行会输出 JSON 格式的分析结果，可直接重定向保存：

   ```bash
   ObfuScan.exe app.apk > result.json
   ```

---

### 从源码编译

#### 环境要求

- CMake ≥ 3.14
- 支持 C++17 的编译器（GCC / Clang / MSVC）
- Git（用于自动拉取 Capstone 依赖）

#### 编译步骤

```bash
git clone https://github.com/1998lixin/ObfuScan.git
cd ObfuScan
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

编译成功后，可执行文件位于：

- Windows: `build/Release/ObfuScan.exe`
- Linux / macOS: `build/ObfuScan`

#### 静态链接（生成无依赖单文件）

在 CMake 配置时添加链接器标志：

```bash
cmake .. -DCMAKE_EXE_LINKER_FLAGS="-static"
```

#### 使用 CLion

如果你使用 CLion 2023+：

1. 直接打开项目目录
2. 等待 CMake 自动配置
3. 选择 Release 配置并构建

---

### 工作原理（评分模型）

ObfuScan 不依赖特征签名，而是采用多因子启发式评分：

| 检测因子 | 含义 | 加分条件（示例） |
|---------|------|----------------|
| 段熵值 | 数据随机性（加密/压缩迹象） | 熵 > 7.0 |
| 分支密度 | 控制流复杂度 | > 12% |
| 间接跳转密度 | OLLVM / VMP 调度器特征 | > 5% |
| 算逻指令密度 | 代码膨胀程度 | > 40% |
| 入口可写段 | 自修改代码嫌疑 | 检测到即加分 |
| .init_array 异常 | 反调试 / 初始化入口数量 | > 20 个 |
| ZIP 伪装 SO | 二次打包容器 | 检测到即显著加分 |

最终分数归一化到 [0,1]，并映射为：

- 高风险 ≥ 0.5
- 中风险 ≥ 0.2
- 低风险 < 0.2

完整评分逻辑可参阅源码 `main.cpp` 中的 `analyze_elf()` 函数。

---

### 当前支持的能力

#### 1. APK 内 arm64-v8a SO 扫描

自动枚举 APK 中的：

```
lib/arm64-v8a/*.so
```

#### 2. ELF 基础分析

支持提取和统计：

- ELF 文件头校验
- Program Header / Section Header
- .text / .rodata / .data / .init_array
- .dynsym / .dynstr
- 导入符号 / 导出符号
- 可执行段熵
- 大块高熵数据
- 是否裁剪符号表（strip）

#### 3. AArch64 指令统计（基于 Capstone）

对 .text 或可执行段进行线性反汇编，统计：

- 分支密度
- 间接跳转密度
- 算术 / 逻辑 / 比较类指令密度

用于辅助判断：

- 疑似 OLLVM
- 疑似强控制流混淆
- 疑似自定义保护逻辑

#### 4. ZIP 容器伪装 SO 识别

有些 APK 里的 .so 条目，实际上并不是裸 ELF，而是 ZIP 容器或二次包装资源。

ObfuScan 支持：

- 识别 ZIP 伪装 SO（检查 `PK\x03\x04` 文件头）
- 自动尝试提取内层 ELF
- 对内层 ELF 继续分析

#### 5. 高风险样本入口预览

对高风险 SO，会进一步尝试预览：

- ELF入口
- .init_array
- JNI_OnLoad
- Java_*
- 名称中包含 init / load / register 的导出函数

输出形式尽量保持简洁，方便快速人工判断。

#### 6. 中文摘要输出

默认输出为中文简洁结果，重点展示：

- SO 文件名
- 检测结果
- 风险等级
- 说明
- 可疑点
- 关键入口预览（高风险样本）
- 建议

适合在大量样本里先看重点，而不是一上来就被技术细节淹没。

---

### 输出结果怎么看

通常可以按这个思路理解：

#### 高风险

**优先看。**

这类目标往往更可能存在：

- 加壳 / loader
- 强混淆
- 可疑初始化逻辑
- 异常入口
- 值得深入跟踪的保护层

#### 中风险

有一定可疑度，但未必真有强保护。适合结合具体业务背景决定是否深入。

#### 低风险

通常更像普通发布版本、基础库、轻度混淆样本。一般不作为第一优先级。

---

### 关于准确率的说明

#### 高风险检测

目前来看，高风险样本的筛选价值相对更高。它的定位不是"百分百准确分类"，而是：

> 尽量把更值得逆向的人先排到前面。

在这个意义上，高风险结果通常更有参考价值。

#### VMP 检测

VMP 检测目前只是启发式参考，不保证准确。

原因很简单：

- 各种自研 VM 差异很大
- 一些强混淆、壳、linker 逻辑也会出现类似特征
- 静态线性反汇编本身就有局限
- 没有做完整的 dispatcher / handler / bytecode 数据流恢复

所以当前版本里：

- "疑似 VMP" = 值得重点看
- 不等于已经确认是 VMP
- "未见明显 VMP 特征" 也不等于绝对没有 VMP

建议把它理解为：**一个帮助你优先级排序的辅助信号**，而不是最终结论。

---

### 一个典型使用思路

实际工作里，我更推荐这样用：

1. 先用 ObfuScan 扫 APK（Web 界面或命令行）
2. 重点看高风险样本
3. 再看这些高风险样本的入口预览
4. 选出最值得深入的几个 SO
5. 再进入：
   - IDA / Ghidra
   - Frida / 自研 JNI 监控
   - 动态跟踪 / 断点调试
   - CFG / dispatcher / handler 深挖

这样通常会比一开始盲开几十上百个 SO 更省时间。

---

### 当前已知局限

- 主要面向 Android 64 位 AArch64 SO（暂不支持 32 位 ARM）
- 不是完整反编译器
- OLLVM / 强混淆判断是启发式
- VMP 检测目前精度有限
- 对某些非常规壳 / 自研 VM / 深度伪装样本可能漏报或误报
- 当前更偏向"前置筛选"而不是"最终定性"

---

### 后续可能的方向

后面可能继续完善的方向包括：

- 接入 AI 辅助判断
- 更稳的入口函数深挖
- 更细的 dispatcher / handler 识别
- 基本块切分（递归反汇编）
- 更强的 OLLVM / flatten 检测
- 更严格的 VMP 结构级识别
- 更详细的可选 verbose 输出
- 批量 APK 目录扫描

---

### 适合谁使用

这个工具更适合：

- 做 Android Native 逆向的人
- 做 APK 安全审计的人
- 需要批量初筛 SO 的研究人员
- 想先快速找高价值目标，再投入深度分析的人

---

### 贡献指南

欢迎任何形式的贡献！无论是：

- 报告 Bug 或提出新功能建议（Issues）
- 提交代码改进（Pull Request）
- 完善文档

请确保代码风格与现有代码保持一致，并在提交前通过编译测试。

---

### 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

### 致谢

感谢以下项目 / 工具：

- **GPT** - 辅助开发与文案优化
- **Capstone** - 轻量级多架构反汇编引擎
- **miniz** - 单文件 ZIP 解压库
- **LibChecker-Rules** - 原生库识别规则

---

## English

### ObfuScan

A lightweight tool for **Android APK Native SO pre-screening**.

The core goal is not to "completely restore logic", but to serve as a **pre-probe before reverse analysis / security audit**, helping you quickly find high-value targets among a bunch of `arm64-v8a` `.so` files.

---

### 📑 Table of Contents

- [Project Positioning](#project-positioning-1)
- [Quick Start](#quick-start-1)
  - [Method 1: Web Interface (Recommended)](#method-1-web-interface-recommended)
  - [Method 2: Command Line](#method-2-command-line)
- [Build from Source](#build-from-source)
- [How It Works (Scoring Model)](#how-it-works-scoring-model)
- [Currently Supported Capabilities](#currently-supported-capabilities)
- [How to Interpret Output Results](#how-to-interpret-output-results)
- [About Accuracy](#about-accuracy)
- [Typical Usage Approach](#typical-usage-approach)
- [Current Known Limitations](#current-known-limitations-1)
- [Possible Future Directions](#possible-future-directions-1)
- [Who It's For](#who-its-for-1)
- [Contributing](#contributing-1)
- [License](#license-1)
- [Acknowledgments](#acknowledgments-1)

---

### Project Positioning

**ObfuScan is not a "fully automatic protection logic restoration" tool.**

It is more like an **outpost before audit**:

- Helps you quickly scan all 64-bit SOs in an APK
- Provides concise risk summaries (Chinese/English)
- Sorts by **high / medium / low** risk levels
- Further displays key entry previews for high-risk samples
- Helps you decide faster:
  - Which SOs are worth looking at first
  - Which entries are worth setting breakpoints / disassembling / dynamic tracking first

In a nutshell:

> **Screen first, then dig deeper.**  
> Prioritize your limited reverse engineering time on targets that are more likely to be valuable.

---

### Quick Start

#### Method 1: Web Interface (Recommended)

1. **Start the Web Server**

   ```bash
   cd ObfuScan
   python web_server.py
   ```

2. **Access the Web Interface**

   Open your browser and visit http://127.0.0.1:8080

3. **Upload APK and Analyze**

   - Click the "Select APK File" button to choose the APK file to analyze
   - Click the "Start Analysis" button
   - Wait for the analysis to complete and view the results

#### Method 2: Command Line

1. **Run ObfuScan**

   ```bash
   ObfuScan.exe <apk_path>
   ```

2. **View / Save Output**

   ```bash
   ObfuScan.exe app.apk > result.json
   ```

---

### Build from Source

#### Requirements

- CMake ≥ 3.14
- C++17 compatible compiler (GCC / Clang / MSVC)
- Git (for automatic Capstone dependency fetch)

#### Build Steps

```bash
git clone https://github.com/1998lixin/ObfuScan.git
cd ObfuScan
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

After a successful build, the executable will be located at:

- Windows: `build/Release/ObfuScan.exe`
- Linux / macOS: `build/ObfuScan`

#### Static Linking (single-file executable)

Add linker flags during CMake configuration:

```bash
cmake .. -DCMAKE_EXE_LINKER_FLAGS="-static"
```

#### Using CLion

If you use CLion 2023+:

1. Open the project directory directly
2. Wait for CMake to auto-configure
3. Select Release configuration and build

---

### How It Works (Scoring Model)

ObfuScan uses multi-factor heuristic scoring rather than signature matching:

| Factor | Meaning | Bonus Condition (example) |
|--------|---------|---------------------------|
| Segment entropy | Data randomness (encryption/compression) | Entropy > 7.0 |
| Branch density | Control flow complexity | > 12% |
| Indirect jump density | OLLVM / VMP dispatcher characteristic | > 5% |
| Arithmetic/logic density | Code bloat | > 40% |
| Entry in writable segment | Self-modifying code suspicion | Detected = +1.0 |
| Excessive .init_array entries | Anti-debug / initialization hooks | > 20 entries |
| ZIP disguised SO | Secondary packaging container | Significant bonus |

The final score is normalized to [0, 1] and mapped to:

- High ≥ 0.5
- Medium ≥ 0.2
- Low < 0.2

See `analyze_elf()` in `main.cpp` for the complete scoring logic.

---

### Currently Supported Capabilities

#### 1. APK arm64-v8a SO Scanning

Automatically enumerates:

```
lib/arm64-v8a/*.so
```

#### 2. ELF Basic Analysis

- ELF header verification
- Program / Section Headers
- .text / .rodata / .data / .init_array
- Symbol tables
- Segment entropy
- Stripped status

#### 3. AArch64 Instruction Statistics (Capstone-based)

- Branch density
- Indirect jump density
- Arithmetic/logical/comparison instruction density

#### 4. ZIP Container Disguised as SO Detection

- Detects `PK\x03\x04` magic header
- Automatically extracts inner ELF for further analysis

#### 5. High-Risk Sample Entry Preview

- ELF entry
- .init_array
- JNI_OnLoad
- Java_*
- Other suspicious exported functions

#### 6. Concise Summary Output

File name, risk level, suspicious points, entry previews, recommendations

---

### How to Interpret Output Results

#### High Risk

**Priority viewing.** Likely contains packing, strong obfuscation, or suspicious initialization.

#### Medium Risk

Some suspicion; decide based on context.

#### Low Risk

Usually standard libraries or lightly obfuscated code.

---

### About Accuracy

#### High-Risk Detection

The screening value for high-risk samples is relatively high. The goal is prioritization, not perfect classification.

#### VMP Detection

VMP detection is heuristic only and not guaranteed. Self-developed VMs, strong obfuscation, and shell logic can produce similar static features. Treat it as a signal to investigate further, not a final verdict.

---

### Typical Usage Approach

1. Scan APK with ObfuScan
2. Focus on high-risk samples
3. Review entry previews
4. Select top candidates for deep analysis in IDA / Ghidra / Frida

---

### Current Known Limitations

- Focuses on Android 64-bit AArch64 SO (32-bit not supported)
- Not a full decompiler
- OLLVM / strong obfuscation detection is heuristic
- VMP detection has limited accuracy
- May miss or false-alarm on unconventional shells / VMs

---

### Possible Future Directions

- AI-assisted scoring
- Deeper entry function analysis
- Basic block splitting (recursive disassembly)
- Stronger OLLVM / flatten detection
- Structural VMP identification
- Batch APK directory scanning

---

### Who It's For

- Android Native reverse engineers
- APK security auditors
- Researchers needing batch SO pre-screening

---

### Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines (or simply open an Issue / PR).

---

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

### Acknowledgments

- **GPT** - Development assistance and documentation
- **Capstone** - Lightweight multi-architecture disassembly engine
- **miniz** - Single-file ZIP decompression library
- **LibChecker-Rules** - Native library identification rules
