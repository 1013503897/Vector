// active_invoke.cpp — see active_invoke.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/active_invoke.h"

#include <jni.h>
#include <time.h>
#include <unistd.h>

#include <cstring>

#include <common/logging.h>

#include "unpack/active_load.h"  // GetAppClassLoaderGlobalRef, ForEachAppClassDescriptor

namespace vector::native::unpack {

namespace {

// java.lang.reflect.Modifier bits we care about.
constexpr jint ACC_STATIC = 0x0008;
constexpr jint ACC_NATIVE = 0x0100;
constexpr jint ACC_ABSTRACT = 0x0400;

long NowMs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

// Cached reflection surface + counters. All jclass/jobject here are GlobalRefs (freed at the end).
struct InvCtx {
    JNIEnv *env = nullptr;

    // Class + reflection entry points.
    jclass cls_Class = nullptr;   // java.lang.Class
    jclass cls_Object = nullptr;  // java.lang.Object (element type of the args array)
    jmethodID mid_forName = nullptr;                 // Class.forName(String,boolean,ClassLoader)
    jmethodID mid_getName = nullptr;                 // Class.getName() (used on param types)
    jmethodID mid_getDeclaredMethods = nullptr;      // Class.getDeclaredMethods()
    jmethodID mid_getDeclaredConstructors = nullptr; // Class.getDeclaredConstructors()
    jmethodID mid_exec_getModifiers = nullptr;       // Executable.getModifiers()
    jmethodID mid_exec_getParamTypes = nullptr;      // Executable.getParameterTypes()
    jmethodID mid_ao_setAccessible = nullptr;        // AccessibleObject.setAccessible(boolean)
    jmethodID mid_m_invoke = nullptr;                // Method.invoke(Object, Object[])
    jmethodID mid_c_newInstance = nullptr;           // Constructor.newInstance(Object[])

    // Boxing of primitive params (valueOf).
    jclass box_Integer = nullptr, box_Long = nullptr, box_Short = nullptr, box_Byte = nullptr,
           box_Char = nullptr, box_Bool = nullptr, box_Float = nullptr, box_Double = nullptr;
    jmethodID vo_int = nullptr, vo_long = nullptr, vo_short = nullptr, vo_byte = nullptr,
              vo_char = nullptr, vo_bool = nullptr, vo_float = nullptr, vo_double = nullptr;

    // Unsafe.allocateInstance (blank instance for instance-method receivers). Null -> skip instance.
    jobject unsafe = nullptr;
    jmethodID mid_allocInstance = nullptr;

    jobject loader = nullptr;  // app ClassLoader (GlobalRef)

    long deadline = 0;         // NowMs() budget cutoff
    bool stop = false;         // set when the budget is exhausted (checked between classes)
    size_t classes = 0, invoked_methods = 0, invoked_ctors = 0;
};

// A default value for one parameter type: boxed zero for primitives, null for refs/arrays. Returns
// a local ref (or null). Reads the type's Class.getName() ("int","long",...) to classify.
jobject BuildDefaultArg(InvCtx *c, jclass paramType) {
    JNIEnv *env = c->env;
    jstring nm = reinterpret_cast<jstring>(env->CallObjectMethod(paramType, c->mid_getName));
    if (env->ExceptionCheck()) { env->ExceptionClear(); if (nm) env->DeleteLocalRef(nm); return nullptr; }
    if (!nm) return nullptr;
    const char *s = env->GetStringUTFChars(nm, nullptr);
    jobject r = nullptr;
    if (s) {
        if (!strcmp(s, "int")) r = env->CallStaticObjectMethod(c->box_Integer, c->vo_int, (jint)0);
        else if (!strcmp(s, "long")) r = env->CallStaticObjectMethod(c->box_Long, c->vo_long, (jlong)0);
        else if (!strcmp(s, "boolean")) r = env->CallStaticObjectMethod(c->box_Bool, c->vo_bool, (jboolean)0);
        else if (!strcmp(s, "byte")) r = env->CallStaticObjectMethod(c->box_Byte, c->vo_byte, (jbyte)0);
        else if (!strcmp(s, "char")) r = env->CallStaticObjectMethod(c->box_Char, c->vo_char, (jchar)0);
        else if (!strcmp(s, "short")) r = env->CallStaticObjectMethod(c->box_Short, c->vo_short, (jshort)0);
        else if (!strcmp(s, "float")) r = env->CallStaticObjectMethod(c->box_Float, c->vo_float, (jfloat)0);
        else if (!strcmp(s, "double")) r = env->CallStaticObjectMethod(c->box_Double, c->vo_double, (jdouble)0);
        // else: reference / array / interface param -> leave null
        env->ReleaseStringUTFChars(nm, s);
    }
    if (env->ExceptionCheck()) { env->ExceptionClear(); r = nullptr; }
    env->DeleteLocalRef(nm);
    return r;
}

// Build an Object[] matching `paramTypes` (a Class[]), filled with default values. Length MUST equal
// the parameter count or the reflective call throws IllegalArgumentException before entering the
// body. Returns a local ref to the array (possibly length 0), or null on allocation failure.
jobjectArray BuildArgs(InvCtx *c, jobjectArray paramTypes) {
    JNIEnv *env = c->env;
    jsize np = paramTypes ? env->GetArrayLength(paramTypes) : 0;
    jobjectArray args = env->NewObjectArray(np, c->cls_Object, nullptr);
    if (!args) { env->ExceptionClear(); return nullptr; }
    for (jsize i = 0; i < np; i++) {
        jclass pt = reinterpret_cast<jclass>(env->GetObjectArrayElement(paramTypes, i));
        if (!pt) continue;
        jobject dv = BuildDefaultArg(c, pt);
        if (dv) {
            env->SetObjectArrayElement(args, i, dv);
            env->DeleteLocalRef(dv);
        }
        env->DeleteLocalRef(pt);
    }
    return args;
}

// Unsafe.allocateInstance(clazz) -> a zero-initialised object with NO constructor run. Local ref, or
// null (abstract / interface / array / primitive class, or Unsafe unavailable).
jobject AllocBlankInstance(InvCtx *c, jclass k) {
    if (!c->unsafe || !c->mid_allocInstance) return nullptr;
    JNIEnv *env = c->env;
    jobject o = env->CallObjectMethod(c->unsafe, c->mid_allocInstance, k);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    return o;
}

// Invoke one Method. `instance`/`inst_tried` cache a per-class blank receiver for instance methods
// (allocated lazily, reused). All refs created here are deleted before return.
void InvokeMethod(InvCtx *c, jclass k, jobject method, jobject *instance, bool *inst_tried) {
    JNIEnv *env = c->env;
    jint mod = env->CallIntMethod(method, c->mid_exec_getModifiers);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    if (mod & (ACC_ABSTRACT | ACC_NATIVE)) return;  // no bytecode CodeItem to restore

    env->CallVoidMethod(method, c->mid_ao_setAccessible, JNI_TRUE);
    if (env->ExceptionCheck()) env->ExceptionClear();

    jobjectArray pts = reinterpret_cast<jobjectArray>(
        env->CallObjectMethod(method, c->mid_exec_getParamTypes));
    if (env->ExceptionCheck()) { env->ExceptionClear(); if (pts) env->DeleteLocalRef(pts); return; }
    jobjectArray args = BuildArgs(c, pts);
    if (pts) env->DeleteLocalRef(pts);

    jobject recv = nullptr;
    if (!(mod & ACC_STATIC)) {
        if (!*inst_tried) {
            *inst_tried = true;
            *instance = AllocBlankInstance(c, k);  // local ref lives in the caller's class frame
        }
        recv = *instance;
        if (!recv) { if (args) env->DeleteLocalRef(args); return; }  // no instance -> skip
    }

    jobject ret = env->CallObjectMethod(method, c->mid_m_invoke, recv, args);
    if (env->ExceptionCheck()) env->ExceptionClear();  // NPE / InvocationTargetException / ... swallowed
    if (ret) env->DeleteLocalRef(ret);
    if (args) env->DeleteLocalRef(args);
    c->invoked_methods++;
}

// Invoke one Constructor via newInstance(defaultArgs). Runs <init> with blank args (side-effect
// risk, but that is what forces a ctor's CodeItem to restore). Exceptions swallowed.
void InvokeCtor(InvCtx *c, jobject ctor) {
    JNIEnv *env = c->env;
    env->CallVoidMethod(ctor, c->mid_ao_setAccessible, JNI_TRUE);
    if (env->ExceptionCheck()) env->ExceptionClear();

    jobjectArray pts = reinterpret_cast<jobjectArray>(
        env->CallObjectMethod(ctor, c->mid_exec_getParamTypes));
    if (env->ExceptionCheck()) { env->ExceptionClear(); if (pts) env->DeleteLocalRef(pts); return; }
    jobjectArray args = BuildArgs(c, pts);
    if (pts) env->DeleteLocalRef(pts);

    jobject obj = env->CallObjectMethod(ctor, c->mid_c_newInstance, args);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (obj) env->DeleteLocalRef(obj);
    if (args) env->DeleteLocalRef(args);
    c->invoked_ctors++;
}

// Per-class callback from ForEachAppClassDescriptor: forName the class, then invoke all of its
// constructors + declared methods. A PushLocalFrame bounds the per-class local-ref churn.
void InvokeClassCb(const char *desc, void *ctxp) {
    auto *c = reinterpret_cast<InvCtx *>(ctxp);
    if (c->stop) return;
    if (NowMs() > c->deadline) { c->stop = true; return; }
    JNIEnv *env = c->env;

    if (env->PushLocalFrame(64) != 0) { env->ExceptionClear(); return; }

    // "Lcom/foo/Bar;" -> "com.foo.Bar"
    char name[512];
    size_t j = 0;
    for (const char *s = desc + 1; *s && *s != ';' && j < sizeof(name) - 1; s++)
        name[j++] = (*s == '/') ? '.' : *s;
    name[j] = 0;
    if (j == 0) { env->PopLocalFrame(nullptr); return; }

    jstring jn = env->NewStringUTF(name);
    jobject ko = jn ? env->CallStaticObjectMethod(c->cls_Class, c->mid_forName, jn, JNI_FALSE,
                                                  c->loader)
                    : nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); env->PopLocalFrame(nullptr); return; }
    if (!ko) { env->PopLocalFrame(nullptr); return; }
    jclass k = reinterpret_cast<jclass>(ko);
    c->classes++;

    // Constructors.
    jobjectArray ctors = reinterpret_cast<jobjectArray>(
        env->CallObjectMethod(k, c->mid_getDeclaredConstructors));
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (ctors) {
        jsize nc = env->GetArrayLength(ctors);
        for (jsize i = 0; i < nc && !c->stop; i++) {
            jobject ct = env->GetObjectArrayElement(ctors, i);
            if (ct) { InvokeCtor(c, ct); env->DeleteLocalRef(ct); }
        }
    }

    // Declared methods (share one lazily-allocated blank instance for the instance ones).
    jobjectArray methods = reinterpret_cast<jobjectArray>(
        env->CallObjectMethod(k, c->mid_getDeclaredMethods));
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (methods) {
        jobject instance = nullptr;
        bool inst_tried = false;
        jsize nm = env->GetArrayLength(methods);
        for (jsize i = 0; i < nm && !c->stop; i++) {
            jobject m = env->GetObjectArrayElement(methods, i);
            if (m) { InvokeMethod(c, k, m, &instance, &inst_tried); env->DeleteLocalRef(m); }
        }
    }

    env->PopLocalFrame(nullptr);

    // Light throttle so the driver does not peg a core / starve the app's own threads.
    if ((c->classes & 63) == 0) usleep(500);
}

// Resolve a static valueOf(prim) boxing method + hold its class as a GlobalRef.
bool ResolveBox(InvCtx *c, const char *cls, const char *sig, jclass *out_cls, jmethodID *out_mid) {
    JNIEnv *env = c->env;
    jclass lc = env->FindClass(cls);
    if (!lc) { env->ExceptionClear(); return false; }
    jmethodID mid = env->GetStaticMethodID(lc, "valueOf", sig);
    if (!mid) { env->ExceptionClear(); env->DeleteLocalRef(lc); return false; }
    *out_cls = reinterpret_cast<jclass>(env->NewGlobalRef(lc));
    *out_mid = mid;
    env->DeleteLocalRef(lc);
    return *out_cls != nullptr;
}

// Best-effort: fetch sun.misc.Unsafe.theUnsafe + allocateInstance. Leaves c->unsafe null on failure
// (instance methods then skipped; static + ctors still run). JNI method/field IDs are not subject to
// Java access checks, so the private theUnsafe field is reachable.
void SetupUnsafe(InvCtx *c) {
    JNIEnv *env = c->env;
    jclass u = env->FindClass("sun/misc/Unsafe");
    if (!u) { env->ExceptionClear(); LOGW("[unpack] invoke: sun.misc.Unsafe unavailable -> instance methods skipped"); return; }
    jfieldID f = env->GetStaticFieldID(u, "theUnsafe", "Lsun/misc/Unsafe;");
    jmethodID alloc = env->GetMethodID(u, "allocateInstance", "(Ljava/lang/Class;)Ljava/lang/Object;");
    if (!f || !alloc) { env->ExceptionClear(); env->DeleteLocalRef(u); LOGW("[unpack] invoke: Unsafe.theUnsafe/allocateInstance unresolved -> instance methods skipped"); return; }
    jobject inst = env->GetStaticObjectField(u, f);
    if (env->ExceptionCheck() || !inst) { env->ExceptionClear(); env->DeleteLocalRef(u); return; }
    c->unsafe = env->NewGlobalRef(inst);
    c->mid_allocInstance = alloc;
    env->DeleteLocalRef(inst);
    env->DeleteLocalRef(u);
    LOGI("[unpack] invoke: Unsafe.allocateInstance ready (instance methods enabled)");
}

void FreeCtx(InvCtx *c) {
    JNIEnv *env = c->env;
    auto del = [&](jobject o) { if (o) env->DeleteGlobalRef(o); };
    del(c->cls_Class); del(c->cls_Object);
    del(c->box_Integer); del(c->box_Long); del(c->box_Short); del(c->box_Byte);
    del(c->box_Char); del(c->box_Bool); del(c->box_Float); del(c->box_Double);
    del(c->unsafe); del(c->loader);
}

}  // namespace

size_t ActiveInvokeAllMethods(void *jni_env, const void *const *classdefs, size_t n, int budget_ms) {
    JNIEnv *env = reinterpret_cast<JNIEnv *>(jni_env);
    if (!env || !classdefs || n == 0) return 0;
    if (budget_ms <= 0) budget_ms = 60000;

    InvCtx c;
    c.env = env;
    c.loader = reinterpret_cast<jobject>(GetAppClassLoaderGlobalRef(env));
    if (!c.loader) { LOGW("[unpack] invoke: no app ClassLoader; skipping Tier-C"); return 0; }

    jclass clsClass = env->FindClass("java/lang/Class");
    jclass clsExec = env->FindClass("java/lang/reflect/Executable");
    jclass clsMethod = env->FindClass("java/lang/reflect/Method");
    jclass clsCtor = env->FindClass("java/lang/reflect/Constructor");
    jclass clsAO = env->FindClass("java/lang/reflect/AccessibleObject");
    jclass clsObject = env->FindClass("java/lang/Object");
    if (!clsClass || !clsExec || !clsMethod || !clsCtor || !clsAO || !clsObject) {
        env->ExceptionClear();
        LOGW("[unpack] invoke: reflection classes unresolved; skipping");
        FreeCtx(&c);
        return 0;
    }
    c.cls_Class = reinterpret_cast<jclass>(env->NewGlobalRef(clsClass));
    c.cls_Object = reinterpret_cast<jclass>(env->NewGlobalRef(clsObject));
    c.mid_forName = env->GetStaticMethodID(
        clsClass, "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
    c.mid_getName = env->GetMethodID(clsClass, "getName", "()Ljava/lang/String;");
    c.mid_getDeclaredMethods =
        env->GetMethodID(clsClass, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    c.mid_getDeclaredConstructors =
        env->GetMethodID(clsClass, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;");
    c.mid_exec_getModifiers = env->GetMethodID(clsExec, "getModifiers", "()I");
    c.mid_exec_getParamTypes =
        env->GetMethodID(clsExec, "getParameterTypes", "()[Ljava/lang/Class;");
    c.mid_ao_setAccessible = env->GetMethodID(clsAO, "setAccessible", "(Z)V");
    c.mid_m_invoke = env->GetMethodID(
        clsMethod, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    c.mid_c_newInstance =
        env->GetMethodID(clsCtor, "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;");
    env->DeleteLocalRef(clsClass); env->DeleteLocalRef(clsExec); env->DeleteLocalRef(clsMethod);
    env->DeleteLocalRef(clsCtor); env->DeleteLocalRef(clsAO); env->DeleteLocalRef(clsObject);

    bool ok = c.cls_Class && c.cls_Object && c.mid_forName && c.mid_getName &&
              c.mid_getDeclaredMethods && c.mid_getDeclaredConstructors && c.mid_exec_getModifiers &&
              c.mid_exec_getParamTypes && c.mid_ao_setAccessible && c.mid_m_invoke &&
              c.mid_c_newInstance;
    ok = ok && ResolveBox(&c, "java/lang/Integer", "(I)Ljava/lang/Integer;", &c.box_Integer, &c.vo_int);
    ok = ok && ResolveBox(&c, "java/lang/Long", "(J)Ljava/lang/Long;", &c.box_Long, &c.vo_long);
    ok = ok && ResolveBox(&c, "java/lang/Short", "(S)Ljava/lang/Short;", &c.box_Short, &c.vo_short);
    ok = ok && ResolveBox(&c, "java/lang/Byte", "(B)Ljava/lang/Byte;", &c.box_Byte, &c.vo_byte);
    ok = ok && ResolveBox(&c, "java/lang/Character", "(C)Ljava/lang/Character;", &c.box_Char, &c.vo_char);
    ok = ok && ResolveBox(&c, "java/lang/Boolean", "(Z)Ljava/lang/Boolean;", &c.box_Bool, &c.vo_bool);
    ok = ok && ResolveBox(&c, "java/lang/Float", "(F)Ljava/lang/Float;", &c.box_Float, &c.vo_float);
    ok = ok && ResolveBox(&c, "java/lang/Double", "(D)Ljava/lang/Double;", &c.box_Double, &c.vo_double);
    if (!ok) {
        env->ExceptionClear();
        LOGW("[unpack] invoke: reflection/boxing method IDs unresolved; skipping");
        FreeCtx(&c);
        return 0;
    }

    SetupUnsafe(&c);  // optional; instance methods degrade to skipped if it fails

    c.deadline = NowMs() + budget_ms;
    LOGI("[unpack] invoke: Tier-C active-invoke starting (budget {}ms)", budget_ms);
    ForEachAppClassDescriptor(classdefs, n, &InvokeClassCb, &c);
    LOGI("[unpack] invoke: classes={} ctors={} methods={} ({})", c.classes, c.invoked_ctors,
         c.invoked_methods, c.stop ? "budget-stopped" : "complete");

    size_t total = c.invoked_methods + c.invoked_ctors;
    FreeCtx(&c);
    return total;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
