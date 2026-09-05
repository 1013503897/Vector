<div align="center">

# Vector Framework

**A high-performance ART hooking framework for modern Android**  
**面向现代 Android 的高性能 ART Hook 框架**

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
> **KPM traceless backend (this fork).** `HookInline`/`UnhookInline` route through a kernel-level
> traceless-hook engine from **[stealth-poc](https://github.com/1013503897/stealth-poc)** (its
> `lib/kpmhook` + `lib/dbi` are vendored into `native/src/kpm`): real libart functions are
> intercepted via UXN page-fault **region clones** / **SSOL** executing from VMA-less ghost memory,
> so the target's `.text` is never modified (CRC- and maps-scan-safe). It falls back to Dobby when
> the KPM bridge is unarmed.

**What this fork adds** (beyond upstream JingMatrix/Vector):

- **KPM traceless backend** — inline hooks leave the target's `.text` unmodified (see the note above).
- **fs-hide** — kernel-side `statfs` / `mountinfo` filtering for injected targets (reader-gated so root's own views stay truthful).
- **Ghost main-path** — hook clones live in VMA-less "ghost" memory.
- **Traceless unpacker** — on-device DEX reconstruction via a KPM clone of ART's `FindClass` (no `.text` patch).
- **SSOL Java-layer hooks** — single-step-out-of-line for dense framework JIT, keeping ART's PC→method map / stack unwind / GC / deopt intact.

### Compatibility

Vector supports devices running **Android 8.1 through Android 17 Beta**.

> [!TIP]
> This framework requires a recent installation of Magisk or KernelSU with Zygisk enabled.

### Installation

1. Download the latest release as a system module.
2. Install the module via your root manager (Magisk / KernelSU).
3. Ensure a Zygisk environment (e.g. [NeoZygisk](https://github.com/JingMatrix/NeoZygisk)).
4. Reboot the device.
5. Access management settings via the system notification.

### Downloads

| Channel | Source |
| :--- | :--- |
| **Stable Releases** | [GitHub Releases](https://github.com/1013503897/Vector/releases) |
| **Canary (CI) Builds** | [GitHub Actions](https://github.com/1013503897/Vector/actions/workflows/core.yml?query=branch%3Amaster) |
| **Upstream (JingMatrix)** | [JingMatrix/Vector](https://github.com/JingMatrix/Vector) |

> [!NOTE]
> Debug builds are recommended for users encountering issues or performing troubleshooting.
> We encourage users to test CI builds to help identify bugs and accelerate development.

> [!CAUTION]
> GitHub requires users to be **logged in** to download CI artifacts.
>
> The link above is filtered to show only `master` branch builds.
> Builds from Pull Requests are often unstable; stay on `master` unless you are helping with debugging.

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
* [stealth-poc](https://github.com/1013503897/stealth-poc): KPM traceless-hook engine vendored into this fork.

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

Vector 是一个 Zygisk 模块，提供与原版 Xposed 保持 API 一致的 ART Hook 框架。它基于 [LSPlant](https://github.com/JingMatrix/LSPlant) 构建，用于提供稳定的 native 级插桩环境。

模块可在内存中修改系统与应用行为；由于不改写 APK 文件，改动是非破坏性的，重启即可还原，并兼容多种 ROM 与 Android 版本。

> [!NOTE]
> **KPM 无痕后端（本 fork）。** `HookInline` / `UnhookInline` 走 **[stealth-poc](https://github.com/1013503897/stealth-poc)** 的内核级无痕 Hook 引擎（`lib/kpmhook` + `lib/dbi` 已 vendor 到 `native/src/kpm`）：通过 UXN 缺页 **region clones** / **SSOL**，在无 VMA 的 ghost 内存中执行，不修改目标 `.text`。KPM bridge 未就绪时回退到 Dobby。

**相对上游 JingMatrix/Vector，本 fork 额外提供：**

- **KPM 无痕后端** — 内联 Hook 不修改目标 `.text`（见上）。
- **fs-hide** — 内核侧对注入目标做 `statfs` / `mountinfo` 过滤（按读者门控，root 自身视图保持真实）。
- **Ghost 主路径** — Hook 克隆位于无 VMA 的 ghost 内存。
- **无痕脱壳** — 通过 ART `FindClass` 的 KPM 克隆在设备上重建 DEX（不打 `.text` 补丁）。
- **SSOL Java 层 Hook** — 针对密集 framework JIT 的 single-step-out-of-line，尽量保持 ART 的 PC→method、栈展开、GC、deopt  intact。

### 兼容性

支持 **Android 8.1 至 Android 17 Beta**。

> [!TIP]
> 需要较新的 Magisk 或 KernelSU，并启用 Zygisk。

### 安装

1. 从 Release 下载最新系统模块。
2. 用 Magisk / KernelSU 安装模块。
3. 确保 Zygisk 环境可用（例如 [NeoZygisk](https://github.com/JingMatrix/NeoZygisk)）。
4. 重启设备。
5. 通过系统通知进入管理界面。

### 下载

| 渠道 | 来源 |
| :--- | :--- |
| **稳定版** | [GitHub Releases](https://github.com/1013503897/Vector/releases) |
| **金丝雀（CI）** | [GitHub Actions](https://github.com/1013503897/Vector/actions/workflows/core.yml?query=branch%3Amaster) |
| **上游（JingMatrix）** | [JingMatrix/Vector](https://github.com/JingMatrix/Vector) |

> [!NOTE]
> 排查问题时建议使用 Debug 构建。也欢迎试 CI 构建，帮助发现缺陷。

> [!CAUTION]
> 下载 CI 产物需要 **登录 GitHub**。
>
> 上方链接已过滤为 `master` 分支构建。PR 构建往往不稳定；除非协助调试，请留在 `master`。

### 支持与贡献

* **排障：** 提交前可先参考 [上游指南](https://github.com/JingMatrix/Vector/issues/123)。
* **讨论：** [GitHub Discussions](https://github.com/JingMatrix/Vector/discussions)（上游社区）。
* **本地化：** [Crowdin](https://crowdin.com/project/lsposed_jingmatrix)。
* **本 fork 的 Issue：** 请开在 [1013503897/Vector](https://github.com/1013503897/Vector/issues)。

> [!IMPORTANT]
> 仅接受基于 **最新 Debug 构建** 的问题反馈。

### 开发者资源

* [Legacy Xposed API](https://api.xposed.info/)
* [Modern libxposed API](https://libxposed.github.io/api/)
* [Xposed Module Repository](https://github.com/Xposed-Modules-Repo)

> [!NOTE]
> Vector 通过两个 git submodule 支持 `libxposed` API：[module API](./xposed/) 与 [service API](./services/)。
>
> [master](https://github.com/1013503897/Vector/tree/master) 分支上成功的 GitHub Actions 构建，表示在对应 commit 上对这些 API 有完整支持。开发时请对齐 Vector 所用的相同 commit。

### 致谢

* [JingMatrix/Vector](https://github.com/JingMatrix/Vector)：本 fork 的上游项目。
* [Magisk](https://github.com/topjohnwu/Magisk/)：Android 定制基础。
* [LSPlant](https://github.com/JingMatrix/LSPlant)：核心 ART Hook 引擎。
* [XposedBridge](https://github.com/rovo89/XposedBridge)：标准 Xposed API。
* [Dobby](https://github.com/JingMatrix/Dobby)：内联 Hook（回退后端；本 fork 主路径为 KPM 无痕引擎）。
* [LSPosed](https://github.com/LSPosed/LSPosed)：上游来源。
* [xz-embedded](https://github.com/tukaani-project/xz-embedded)：解压工具库。
* [stealth-poc](https://github.com/1013503897/stealth-poc)：本 fork 引入的 KPM 无痕 Hook 引擎。

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
