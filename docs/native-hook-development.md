# Vector Native Hook 开发指南

用 Vector 自带的插桩设施写 native hook 来调试/分析 app，**不需要 frida**。你的 hook 还会
**自动继承 KPM 无痕后端**（bridge 起了走 traceless，没起退回 Dobby），这是 frida 给不了的。

本文覆盖三条路、完整 ABI、符号解析、后端行为、构建/部署/看日志，以及一个可直接编译运行的
样例模块（`tools/hookmodule/`）。

---

## 0. TL;DR

| 你想要 | 用哪条路 |
|---|---|
| 干净、可反复迭代、自动 stealth、不动 Vector 主体 | **路线 1**：独立 native 模块 `.so`（NativeAPIEntries ABI） |
| 一次性临时调试、就想快 | **路线 2**：树内直接用 `HookInline` / lsplant DSL |
| hook ART 内部 / Java 方法 | **路线 3**：lsplant DSL + worker 线程（参照 unpacker） |

样例模块已写好并编译验证：`tools/hookmodule/libs/arm64-v8a/libvechook.so`（导出 `native_init`，
arm64-v8a，minSdk 27）。它对一个 DexProtector 加固的 Flutter app
做了三件事：打印每次 `dlopen`、hook `openat`（看文件访问）、hook `__system_property_get`
（看指纹/反模拟器读取），并演示了"库加载后再 hook 它导出符号"的 late-hook 模板。

---

## 1. 路线 1：独立 native 模块（推荐）

这是 Vector 专门为"写 native hook 调 app"设计的路径，血统来自 Riru/LSPosed 的 native module 机制。

### 1.1 运行时流程

```
Vector 框架                              你的模块 (libvechook.so)
-----------                              -----------------------
[ do_dlopen hook 已挂 (native_api.cpp) ]
        │
  目标进程 dlopen(libvechook.so)
        │ 名字命中已注册列表
        ├──────────►  调用你导出的 native_init(entries)
        │                     │ 存下 hookFunc/unhookFunc，装即时 hook
        │  ◄──────────────────┤ 返回 NativeOnModuleLoaded 回调
        │
  之后每次 dlopen 任意 .so ──►  回调(name, handle)  ← 库加载可观测 + late-hook 时机
```

关键源码锚点：
- ABI 定义：`native/include/core/native_api.h`
- `do_dlopen` hook + 模块分发：`native/src/core/native_api.cpp:157`（`do_dlopen_hook`）
- `hookFunc` 实体 = `HookInline`：`native/include/core/native_api.h:147`（先试 KPM，失败退 Dobby）
- 注册入口（JNI）：`native/src/jni/native_api_bridge.cpp:6` → `RegisterNativeLib`

### 1.2 ABI（你只需 mirror 这一小段）

```cpp
using HookFunType   = int (*)(void *func, void *replace, void **backup);
using UnhookFunType = int (*)(void *func);
using NativeOnModuleLoaded = void (*)(const char *name, void *handle);

struct NativeAPIEntries {
    uint32_t version;          // Vector 目前传 2
    HookFunType hookFunc;      // inline hook（KPM-traceless / Dobby 自动选）
    UnhookFunType unhookFunc;  // inline unhook
};

// 你必须导出这个符号：
extern "C" NativeOnModuleLoaded native_init(const NativeAPIEntries *entries);
```

- `hookFunc(target, replace, &backup)`：返回 0 成功，`backup` 是"调用原始函数"的指针。
- 回调 `native_init` 返回的函数：**每次** `dlopen` 后触发，给你库名 + handle。
  - 这是"列出加载了哪些库"的零成本可观测点；
  - 也是给"native_init 时还没加载"的目标库做 late-hook 的唯一时机（库刚 map 好，符号就位）。

完整样例见 `tools/hookmodule/jni/vechook.cpp`，含 **re-entrancy guard**（hook 里调
`__android_log_print` 首次会触发 `openat` → 不加守卫会 `openat→log→openat` 递归）。

### 1.3 构建

```bash
NDK="$ANDROID_HOME/ndk/29.0.13113456"          # 项目同款 NDK（build.gradle.kts: androidCompileNdkVersion）
cd tools/hookmodule
"$NDK/ndk-build.cmd" NDK_PROJECT_PATH=. \
    NDK_APPLICATION_MK=./jni/Application.mk \
    APP_BUILD_SCRIPT=./jni/Android.mk
# -> libs/arm64-v8a/libvechook.so
```

`Application.mk`：`APP_ABI=arm64-v8a`、`APP_PLATFORM=android-27`、`APP_STL=c++_static`
（静态链 STL，模块自包含，不依赖目标进程的 libc++_shared）。

校验导出：
```bash
"$NDK/toolchains/llvm/prebuilt/*/bin/llvm-readelf" --dyn-syms libs/arm64-v8a/libvechook.so | grep native_init
# 21: 0000...0e6c  176 FUNC GLOBAL DEFAULT 13 native_init   ← 已导出
```

### 1.4 部署（打成 Xposed 模块，在 Vector 管理器里启用）

Vector 是 LSPosed 派生框架，native 模块走 Xposed 模块加载链：

1. **声明 native 库名**：模块 APK 内放 `META-INF/xposed/native_init.list`，每行一个库名：
   ```
   libvechook.so
   ```
   （libxposed API 约定，见 `xposed/libxposed/api/.../package-info.java`）
2. **放 .so**：`lib/arm64-v8a/libvechook.so` 打进模块 APK。
3. **触发加载**：模块的 Java/Kotlin 入口（标准 Xposed 模块，AndroidManifest 带
   `xposedmodule` meta-data）在目标进程里 `System.loadLibrary("vechook")`，这步会 `dlopen`
   你的 `.so` → Vector 的 `do_dlopen` hook 命中已注册名 → 调 `native_init`。
4. **启用 + 限定作用域**：在 Vector 管理器里启用该模块，作用域勾选目标 app。
5. 启动目标 app → `native_init` 触发 → hook 安装 → 看日志。

加载时管理器对每个声明的库名调 `NativeAPI.recordNativeEntrypoint(name)`
（`VectorModuleManager.kt:101`）→ C++ `RegisterNativeLib`。

### 1.5 看日志

```bash
adb -s <设备> logcat -s vechook:V          # 你的模块
# 期望：native_init -> hooked openat -> hooked __system_property_get -> dlopen: ... 流水
```

确认 KPM 后端是否生效：日志若打印 `KPM inline hook failed ... falling back to Dobby`
（Vector tag）说明走了 Dobby（仍可用，只是有 inline 痕迹）；要 traceless 需先 boot-time
起 bridge（见 `kpm-device-test-workflow` / `kpm-probe`）。

---

## 2. 路线 2：树内临时 hook（最快）

只想临时调试、不想打模块包，直接在 native 源码里用现成 API：

```cpp
#include "core/native_api.h"
using namespace vector::native;

static int (*orig)(const char*, int);
static int my(const char* p, int f) { LOGD("open %s", p); return orig(p, f); }

void *t = ElfSymbolCache::GetLinker()->getSymbAddress("...");   // 解析目标
HookInline(t, (void*)&my, (void**)&orig);                       // 自动 KPM/Dobby
// ... UnhookInline(t);
```

`HookInline`/`UnhookInline` 同样自动走 KPM/Dobby（`native_api.h:147/176`）。

---

## 3. 路线 3：hook ART 内部 / Java 方法

用 lsplant 的 C++20 hooking DSL（文档在 `native/src/core/native_api.cpp:20-79`）：

```cpp
inline static auto h = "__open"_sym.hook ->* []<auto backup>(const char *p, int f) {
    LOGD("open %s", p);
    return backup(p, f);
};
// 注册：handler(h);
```

ART 内部符号解析、worker 线程模式参照脱壳机：`native/src/unpack/unpacker.cpp:87`
（`WorkerMain`：在 `postAppSpecialize` 起 detached worker，attach ART，装/卸 hook）
和 `native/src/unpack/choke_hook.cpp:57`（`ResolveChoke`，用 `ElfImage` 从 libart
`.dynsym ∪ .gnu_debugdata` 解析 `ArtMethod::GetCodeItem` 等内部符号）。

---

## 4. 符号解析（三条路通用）

别手写 ELF 解析，用 `native/include/elf/elf_image.h` + `symbol_cache.h`：

```cpp
const auto *art = ElfSymbolCache::GetArt();                 // libart，含 .gnu_debugdata(LZMA .symtab)
void *fn = art->getSymbAddress("_ZN3art9ArtMethod6InvokeE...");
void *e  = art->getSymbPrefixFirstAddress("_ZN3art11interpreter7ExecuteE");  // C++ 局部符号带后缀时用前缀
// 任意库：ElfImage img("libfoo.so"); img.getSymbAddress("bar");
```

连 stripped libart 的 `.gnu_debugdata` 里的 `.symtab` 都能解析（`elf_image.cpp`）。

---

## 5. 后端：KPM-traceless vs Dobby

`HookInline`（即模块拿到的 `hookFunc`）逻辑（`native_api.h:147`）：

1. `kpm_hook_init() == 0`（bridge 已 boot-time 武装）→ 试 `kpm_inline_hooker`：
   UXN-trap 目标整页，整页 DBI clone 跑原始，目标 `.text` **不改**（CRC 干净，maps/smaps 隐藏）。
   `backup` = clone 里目标的忠实副本。
2. KPM 不可用 / 此目标 clone 不了 → 退 `DobbyHook`（标准 inline，有 trampoline 痕迹）。

**对模块作者透明**：你永远只调 `hookFunc`，stealth 与否由 Vector 决定。
边界：单页 clone 假设被 hook 函数体在一页内；跨多页函数（如 `art::interpreter::Execute`）
需未实现的多页 clone。普通目标函数没问题。

---

## 6. 样例模块清单（`tools/hookmodule/`）

```
tools/hookmodule/
├── jni/
│   ├── vechook.cpp        # 模块源码（ABI + 3 个 hook + late-hook 模板 + re-entrancy guard）
│   ├── Android.mk
│   └── Application.mk     # arm64-v8a / android-27 / c++_static
├── libs/arm64-v8a/
│   └── libvechook.so      # 构建产物（导出 native_init）
└── README.md
```

改成你自己的目标：把 `vechook.cpp` 里 `hook_symbol("openat", ...)` 换成你的目标符号，
或在 `on_module_loaded` 里把 `strstr(name, "libflutter.so")` + `dlsym(handle, "JNI_OnLoad")`
换成你要 late-hook 的库与导出符号。

---

## 7. 排错

| 现象 | 原因 / 处理 |
|---|---|
| `native_init` 不触发 | 模块 `.so` 没在目标进程被 `dlopen`（确认 Java 侧 `System.loadLibrary` + 名字在 `native_init.list` + 管理器里模块已启用且作用域含目标 app） |
| hook 装上但不打印 | re-entrancy guard 吞了（log 自身触发）或目标函数没被调用；换更热的符号验证 |
| app 崩 / pc=0 | 跨页函数被单页 clone，或 hook 了 ART 内部却没在 runnable 线程；参照 unpacker 的 fault-guard |
| 日志显示 falling back to Dobby | KPM bridge 没起；要 traceless 先 boot-time `shctl <KEY> load shpte.kpm; control shpte probe; control shpte bridge` |

---

## 附：实测记录（2026-06-23）

- 目标：一个 DexProtector 加固的 Flutter app（native 含 ML Kit OCR / OpenCV / TFLite / face 库）。
- 设备：Pixel 6（oriole，Android 16，APatch + Vector）。
- 结果：XAPK 5-split `install-multiple` 成功，启动到通知权限弹窗（splash 正常转），
  **未崩溃、未 root 拦截、未区域闪退**，DexProtector 初始启动通过。
- 模块：`libvechook.so` 已编译并验证导出 `native_init`；端到端注入测试（打模块包 + 管理器
  启用 + 看 hook 日志）是下一步。
