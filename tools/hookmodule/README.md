# vechook — Vector native hook module (sample)

A standalone, compilable example of Vector's **native module ABI** (route 1). It hooks an app's
file I/O and property reads, logs every library load, and shows the late-hook pattern — all via
Vector's `hookFunc`, so the hooks run on the **KPM-traceless backend when armed** and fall back
to Dobby otherwise.

Full guide: [`../../docs/native-hook-development.md`](../../docs/native-hook-development.md).

## Build

```bash
NDK="$ANDROID_HOME/ndk/29.0.13113456"
cd tools/hookmodule
"$NDK/ndk-build.cmd" NDK_PROJECT_PATH=. NDK_APPLICATION_MK=./jni/Application.mk APP_BUILD_SCRIPT=./jni/Android.mk
# -> libs/arm64-v8a/libvechook.so   (exports native_init)
```

## What it hooks

| Hook | Why |
|---|---|
| every `dlopen` (via the framework callback) | loader observability, zero target knowledge |
| `openat` | every file the app opens (DexProtector asset reads, etc.) |
| `__system_property_get` | every system property read (fingerprint / anti-emulator) |
| `libflutter.so!JNI_OnLoad` (late-hook template) | demonstrates hooking a target lib's own export once mapped |

## Deploy

Package as an Xposed module (declare `libvechook.so` in `META-INF/xposed/native_init.list`, ship
the `.so` in `lib/arm64-v8a/`, `System.loadLibrary("vechook")` from the module's Java entry),
enable it in the Vector manager scoped to the target app, launch the app, then:

```bash
adb -s <device> logcat -s vechook:V
```

See the guide for the full deployment + troubleshooting steps.
