<div align="center">

# Vector Framework

**A Zygisk ART Hooking Framework with KPM Traceless Backend**  
**集成 KPM 内核无痕后端的 Zygisk ART Hook 框架**

[English](#english) · [中文](#中文)

[![Build](https://img.shields.io/github/actions/workflow/status/1013503897/Vector/core.yml?branch=master&event=push&logo=github&label=Build)](https://github.com/1013503897/Vector/actions/workflows/core.yml?query=event%3Apush+branch%3Amaster+is%3Acompleted)
[![Crowdin](https://img.shields.io/badge/Localization-Crowdin-blueviolet?logo=Crowdin)](https://crowdin.com/project/lsposed_jingmatrix)
[![Download](https://img.shields.io/github/v/release/1013503897/Vector?color=orange&logoColor=orange&label=Download&logo=DocuSign)](https://github.com/1013503897/Vector/releases/latest)
[![Total](https://img.shields.io/github/downloads/1013503897/Vector/total?logo=Bookmeter&label=Counts&logoColor=yellow&color=yellow)](https://github.com/1013503897/Vector/releases)

Fork of [JingMatrix/Vector](https://github.com/JingMatrix/Vector) · 基于上游 [JingMatrix/Vector](https://github.com/JingMatrix/Vector)

</div>

---

<a id="english"></a>

## English

### Introduction

Vector is a Zygisk module providing an ART hooking framework that maintains API consistency with the original Xposed. It is engineered on top of [LSPlant](https://github.com/JingMatrix/LSPlant) to deliver a stable, native-level instrumentation environment.

The framework allows modules to modify system and application behavior in-memory. Because no APK files are modified, changes are non-destructive, easily reversible via reboot, and compatible across various ROMs and Android versions.

> [!NOTE]
> **KPM traceless backend (this fork):** `HookInline`/`UnhookInline` route through the kernel-level
> traceless-hook engine from **[stealth-core](https://github.com/1013503897/stealth-core)** (`lib/kpmhook`
> and `lib/dbi` vendored in `native/src/kpm`). Native libart functions are intercepted via UXN
> page-fault **region clones** / **SSOL** in VMA-less ghost memory, leaving the target `.text`
> unmodified to pass memory CRC and `/proc/maps` scans. Falls back to Dobby when the KPM bridge is unarmed.

**Fork Features** (beyond upstream JingMatrix/Vector):

- **KPM Traceless Backend**: Inline hooks do not modify target `.text` bytes (see note above).
- **Kernel-side fs-hide**: Transparently filter `statfs` and `mountinfo` for target processes via reader gating.
- **Ghost Memory Execution**: Hook clone code runs in unmapped VMA-less memory invisible to `/proc/*/maps` and `mincore`.
- **Traceless Unpacker**: On-device DEX extraction hooking ART `FindClass` without modifying runtime `.text`.
- **SSOL Java Hooking**: Single-step-out-of-line execution for framework JIT methods, keeping ART method tables, stack unwinding, GC, and deopt intact.

### Compatibility

Android **8.1 through Android 17 Beta** (ARM64). Requires Magisk or KernelSU with Zygisk enabled.

### Installation

1. Download the release module zip.
2. Flash the module via your root manager (Magisk / KernelSU / APatch).
3. Ensure a working Zygisk environment (e.g. NeoZygisk / Zygisk Next).
4. Reboot the device.
5. Configure modules and scopes through the manager UI or CLI.

### Downloads

| Channel | Source |
| :--- | :--- |
| **Stable Releases** | [GitHub Releases](https://github.com/1013503897/Vector/releases) |
| **CI Builds** | [GitHub Actions](https://github.com/1013503897/Vector/actions/workflows/core.yml?query=branch%3Amaster) |
| **Upstream** | [JingMatrix/Vector](https://github.com/JingMatrix/Vector) |

* CI artifact downloads require a GitHub login.
* Builds on `master` branch are recommended for testing. Debug builds provide verbose logging for troubleshooting.

### Support and Contribution

* **Troubleshooting:** Consult the [upstream guide](https://github.com/JingMatrix/Vector/issues/123) before reporting bugs.
* **Discussions:** [GitHub Discussions](https://github.com/JingMatrix/Vector/discussions) (upstream community).
* **Localization:** [Crowdin](https://crowdin.com/project/lsposed_jingmatrix).
* **Issues for this fork:** open issues on [1013503897/Vector](https://github.com/1013503897/Vector/issues).

> [!IMPORTANT]
> Bug reports are only accepted if they are based on the **latest debug build**.

### Developer Resources

* [Legacy Xposed API](https://api.xposed.info/)
* [Modern libxposed API](https://libxposed.github.io/api/)
* [Xposed Module Repository](https://github.com/Xposed-Modules-Repo)

> [!NOTE]
> Vector supports the `libxposed` API via two git submodules: the [module API](./xposed/) and the [service API](./services/).
>
> A successful GitHub Actions build of the [master](https://github.com/1013503897/Vector/tree/master) branch indicates that Vector fully supports these APIs at those specific commits.
> Developers should check out the same commits as Vector.

### Credits

* [JingMatrix/Vector](https://github.com/JingMatrix/Vector): upstream project this fork is based on.
* [Magisk](https://github.com/topjohnwu/Magisk/): foundation of Android customization.
* [LSPlant](https://github.com/JingMatrix/LSPlant): core ART hooking engine.
* [XposedBridge](https://github.com/rovo89/XposedBridge): standard Xposed APIs.
* [Dobby](https://github.com/JingMatrix/Dobby): inline hooking (fallback backend; this fork's primary is the KPM traceless engine).
* [LSPosed](https://github.com/LSPosed/LSPosed): upstream source.
* [xz-embedded](https://github.com/tukaani-project/xz-embedded): library decompression utilities.
* [stealth-core](https://github.com/1013503897/stealth-core): KPM traceless-hook engine vendored into this fork.

<details>
<summary>Legacy and Historical Dependencies</summary>

- ~~[Riru](https://github.com/RikkaApps/Riru)~~
- ~~[SandHook](https://github.com/ganyao114/SandHook/)~~
- ~~[YAHFA](https://github.com/rk700/YAHFA)~~
- ~~[dexmaker](https://github.com/linkedin/dexmaker)~~
- ~~[DexBuilder](https://github.com/LSPosed/DexBuilder)~~
</details>

### License

Vector is licensed under the [GNU General Public License v3](http://www.gnu.org/copyleft/gpl.html).

---

<a id="中文"></a>

## 中文

### 简介

Vector 是一个基于 [LSPlant](https://github.com/JingMatrix/LSPlant) 的 Zygisk 模块，提供兼容原生 Xposed API 的 Native 级 ART Hook 运行时。

本分支的核心演进在于**将底层 Inline Hook 后端接入内核级无痕引擎**：通过引入 [stealth-core](https://github.com/1013503897/stealth-core) 的 KPM 模块，使框架在注入与拦截过程中无需改写目标进程的代码段（`.text`），以此抵御严格的反作弊、内存完整性自校验与 `/proc/maps` 内存特征扫描。

### 分支增强特性

- **KPM 内核无痕后端**：`HookInline` / `UnhookInline` 优先路由至 `stealth-core`。通过 UXN 缺页异常触发，在无 VMA 的 ghost 内存中执行 DBI 重编译克隆或 SSOL 单步模拟，目标 `.text` 原始字节一字不改。KPM 通道未武装时自动回退至 Dobby。
- **内核级文件系统隐藏 (fs-hide)**：内核拦截目标进程的 `statfs` 与 `mountinfo` 调用，屏蔽 Magisk 与 OverlayFS 挂载特征（读进程门控，保持 root 视图真实）。
- **Ghost 内存执行**：Hook 克隆段位于未挂载 VMA 的物理映射页中，免疫 `/proc/*/maps` 遍历与 `mincore` 扫描。
- **内存无痕脱壳**：通过 KPM 劫持 ART `FindClass`，在不打 `.text` 补丁的前提下在设备端抓取并重建内存 DEX。
- **SSOL Java 方法 Hook**：面向 Android Framework 高频 JIT 代码的单步出线执行，维持 ART 方法表映射、栈回溯、GC 与 deopt 的原生行为。

### 兼容性

支持 **Android 8.1 至 Android 17 Beta**（ARM64）。运行依赖 Magisk / KernelSU / APatch 及其 Zygisk 实现（如 NeoZygisk / Zygisk Next）。

### 安装方式

1. 从 Release 页面下载模块压缩包。
2. 在 Root 管理器（Magisk / KernelSU / APatch）中刷入模块。
3. 确保 Zygisk 环境正常运行。
4. 重启设备。
5. 通过系统通知或管理器 CLI 配置模块与作用域。

### 产物与渠道

| 渠道 | 链接 |
| :--- | :--- |
| **稳定版本** | [GitHub Releases](https://github.com/1013503897/Vector/releases) |
| **CI 构建** | [GitHub Actions](https://github.com/1013503897/Vector/actions/workflows/core.yml?query=branch%3Amaster) |
| **上游原项目** | [JingMatrix/Vector](https://github.com/JingMatrix/Vector) |

* CI 产物下载需登录 GitHub。
* 排查 Hook 故障与异常时，推荐切换至 Debug 构建获取详细诊断日志。

### 支持与讨论

* **排障参考：** 提 issue 前可先查阅 [上游指南](https://github.com/JingMatrix/Vector/issues/123)。
* **上游讨论区：** [GitHub Discussions](https://github.com/JingMatrix/Vector/discussions)。
* **本地化翻译：** [Crowdin](https://crowdin.com/project/lsposed_jingmatrix)。
* **本分支 Issue：** 请提交至 [1013503897/Vector](https://github.com/1013503897/Vector/issues)。

### 开发者资源

* [Legacy Xposed API](https://api.xposed.info/)
* [Modern libxposed API](https://libxposed.github.io/api/)
* [Xposed Module Repository](https://github.com/Xposed-Modules-Repo)

> [!NOTE]
> Vector 通过两个 git submodule 支持 `libxposed` API：[module API](./xposed/) 与 [service API](./services/)。开发时请对齐 Vector 所引用的对应 commit。

### 致谢

* [JingMatrix/Vector](https://github.com/JingMatrix/Vector)：本 fork 的上游项目。
* [Magisk](https://github.com/topjohnwu/Magisk/)：Android 定制基础。
* [LSPlant](https://github.com/JingMatrix/LSPlant)：核心 ART Hook 引擎。
* [XposedBridge](https://github.com/rovo89/XposedBridge)：标准 Xposed API。
* [Dobby](https://github.com/JingMatrix/Dobby)：内联 Hook 回退后端。
* [LSPosed](https://github.com/LSPosed/LSPosed)：上游源码基础。
* [xz-embedded](https://github.com/tukaani-project/xz-embedded)：解压工具库。
* [stealth-core](https://github.com/1013503897/stealth-core)：本 fork 引入的 KPM 内核级无痕 Hook 引擎。

<details>
<summary>历史依赖</summary>

- ~~[Riru](https://github.com/RikkaApps/Riru)~~
- ~~[SandHook](https://github.com/ganyao114/SandHook/)~~
- ~~[YAHFA](https://github.com/rk700/YAHFA)~~
- ~~[dexmaker](https://github.com/linkedin/dexmaker)~~
- ~~[DexBuilder](https://github.com/LSPosed/DexBuilder)~~
</details>

### 许可证

Vector 采用 [GNU General Public License v3](http://www.gnu.org/copyleft/gpl.html)。
