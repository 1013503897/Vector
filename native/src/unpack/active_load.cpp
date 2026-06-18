// active_load.cpp — see active_load.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/active_load.h"

#include <jni.h>
#include <cstdio>
#include <cstring>
#include <vector>

#include <common/logging.h>

#include "unpack/dex_layout.h"

namespace vector::native::unpack {

namespace {

// Readable /proc/self/maps regions + an app/framework classification. We only scan APP regions
// (anonymous, or under /data) for dexes — framework dexes (/system, /apex, ...) are already
// un-extracted and loading their classes wastes time + risks side effects.
struct Maps {
    struct R {
        uintptr_t s, e;
        bool app;
    };
    std::vector<R> r;
    void load() {
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) return;
        char line[600];
        while (fgets(line, sizeof(line), f)) {
            uintptr_t s = 0, e = 0;
            char perms[5] = {0};
            if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
            if (perms[0] != 'r') continue;
            const char *path = strchr(line, '/');   // pathname (if any) starts at the first '/'
            bool app = true;
            if (path) {
                app = !(strncmp(path, "/system", 7) == 0 || strncmp(path, "/apex", 5) == 0 ||
                        strncmp(path, "/vendor", 7) == 0 || strncmp(path, "/product", 8) == 0 ||
                        strncmp(path, "/system_ext", 11) == 0 || strncmp(path, "/dev", 4) == 0);
            }
            r.push_back({s, e, app});
        }
        fclose(f);
    }
    const R *find(uintptr_t a) const {
        for (const auto &x : r)
            if (a >= x.s && a < x.e) return &x;
        return nullptr;
    }
};

struct FNCtx {
    JNIEnv *env;
    jclass cls_class;
    jmethodID for_name;
    jobject loader;
    size_t loaded;
    size_t failed;
};

// Class.forName("com.foo.Bar", false, appLoader) — loads + links the class (the point a dpt-style
// per-class extraction shell restores its CodeItems), WITHOUT running <clinit> (initialize=false
// avoids static-init side effects). Descriptor "Lcom/foo/Bar;" -> dotted name.
void ForNameCb(const char *desc, void *ctxp) {
    auto *c = reinterpret_cast<FNCtx *>(ctxp);
    char name[512];
    size_t j = 0;
    for (const char *s = desc + 1; *s && *s != ';' && j < sizeof(name) - 1; s++)
        name[j++] = (*s == '/') ? '.' : *s;
    name[j] = 0;
    if (j == 0) return;
    JNIEnv *env = c->env;
    jstring jn = env->NewStringUTF(name);
    if (!jn) {
        env->ExceptionClear();
        return;
    }
    jobject k = env->CallStaticObjectMethod(c->cls_class, c->for_name, jn, JNI_FALSE, c->loader);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        c->failed++;
    } else {
        c->loaded++;
    }
    if (k) env->DeleteLocalRef(k);
    env->DeleteLocalRef(jn);
}

// app ClassLoader = ActivityThread.currentApplication().getClassLoader(). Returned as a GlobalRef
// (stable across the load loop); caller deletes it.
jobject GetAppClassLoader(JNIEnv *env) {
    jclass at = env->FindClass("android/app/ActivityThread");
    if (!at) {
        env->ExceptionClear();
        return nullptr;
    }
    jmethodID cur = env->GetStaticMethodID(at, "currentApplication", "()Landroid/app/Application;");
    if (!cur) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject app = env->CallStaticObjectMethod(at, cur);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    if (!app) return nullptr;
    jclass ctx = env->FindClass("android/content/Context");
    if (!ctx) {
        env->ExceptionClear();
        return nullptr;
    }
    jmethodID get_cl = env->GetMethodID(ctx, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_cl) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject loader = env->CallObjectMethod(app, get_cl);
    if (env->ExceptionCheck() || !loader) {
        env->ExceptionClear();
        return nullptr;
    }
    return env->NewGlobalRef(loader);
}

}  // namespace

size_t ActiveLoadAllClasses(void *jni_env, const void *const *classdefs, size_t n) {
    JNIEnv *env = reinterpret_cast<JNIEnv *>(jni_env);
    if (!env || !classdefs || n == 0) return 0;

    jobject loader = GetAppClassLoader(env);
    if (!loader) {
        LOGW("[unpack] activeload: could not get app ClassLoader; skipping");
        return 0;
    }
    jclass cls_class = env->FindClass("java/lang/Class");
    jmethodID for_name = cls_class ? env->GetStaticMethodID(
        cls_class, "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;")
                                   : nullptr;
    if (!for_name) {
        env->ExceptionClear();
        env->DeleteGlobalRef(loader);
        LOGW("[unpack] activeload: Class.forName unresolved; skipping");
        return 0;
    }

    Maps maps;
    maps.load();

    // Distinct APP regions that contain at least one enumerated ClassDef — these hold the app dexes.
    std::vector<std::pair<uintptr_t, uintptr_t>> regions;
    for (size_t i = 0; i < n; i++) {
        const Maps::R *r = maps.find(reinterpret_cast<uintptr_t>(classdefs[i]));
        if (!r || !r->app) continue;
        bool seen = false;
        for (auto &q : regions)
            if (q.first == r->s) {
                seen = true;
                break;
            }
        if (!seen) regions.emplace_back(r->s, r->e);
    }
    if (regions.empty()) {
        env->DeleteGlobalRef(loader);
        LOGW("[unpack] activeload: no app dex regions among {} class-defs", n);
        return 0;
    }

    FNCtx ctx{env, cls_class, for_name, loader, 0, 0};
    size_t dexes = 0;
    for (auto &reg : regions) {
        const uint8_t *region_start = reinterpret_cast<const uint8_t *>(reg.first);
        const uint8_t *region_end = reinterpret_cast<const uint8_t *>(reg.second);
        const uint8_t *from = region_start;
        while (true) {
            const uint8_t *base = dex::LocateDexByInvariants(from, region_end);
            if (!base) break;
            dexes++;
            dex::EnumerateClassDescriptors(base, region_end, &ForNameCb, &ctx);
            uint32_t fsz = dex::DexFileSize(base);
            const uint8_t *next = base + (fsz ? fsz : 0x70);
            if (next <= from) break;   // no progress -> avoid an infinite loop
            from = next;
        }
    }

    env->DeleteGlobalRef(loader);
    LOGI("[unpack] activeload: {} app dex(es) in {} region(s) -> forName loaded={} failed={}", dexes,
         regions.size(), ctx.loaded, ctx.failed);
    return ctx.loaded;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
