package org.matrix.vector.daemon.unpack

import android.os.SystemProperties
import android.util.Log
import java.io.File

/**
 * Canonical preset -> prop contract for the Vector stealth unpacker
 * (native/src/unpack, driven by persist.kpmhook.unpack.*).
 *
 * This is the Kotlin twin of tools/vunpack/vunpack (the on-device shell front-end).
 * The two MUST stay in sync: same TUNING list, same preset prop sets, same validation.
 * The manager UI reaches the unpacker through this object (via CliHandler today, and a
 * ManagerService/AIDL method later) so there is exactly one place that knows the recipes.
 *
 * Props are set through resetprop (the proven mechanism the README + vunpack use), NOT
 * SystemProperties.set -- a custom persist. prop is not reliably settable through the
 * property service from the daemon's SELinux domain. Reads go through SystemProperties.
 */
object UnpackConfig {
  private const val TAG = "VectorUnpack"

  const val MASTER = "persist.kpmhook.unpack" // master enable
  const val TARGET = "persist.kpmhook.target" // process nice-name gate (separate namespace)
  private const val NS = "persist.kpmhook.unpack" // tuning props live under NS.<key>

  /**
   * Every tuning prop this object may set -- cleared on disarm() so a stale flag from a
   * previous preset can never leak into the next run. Keep in sync with
   * ReadConfigFromProps() + the PropInt reads in unpacker.cpp, and with vunpack's TUNING.
   * NB: gcashfix/gcashopenat are deliberately NOT here (special-purpose GCash modes, not
   * general unpack presets -- clearing them could disrupt a GCash session).
   */
  private val TUNING =
      listOf(
          "stealth", "traceless", "dexfind", "trigger", "interp", "activeload", "extout",
          "interp_ms", "worker_delay_ms", "predelay_ms", "rounds", "interval_ms",
          "tier", "choke", "openat", "openat_ms", "openat_dobby")

  /** Flags that also affect a run but live outside the unpack namespace (shown, never cleared). */
  private val EXTERNAL = listOf("persist.kpmhook.fshide", "persist.kpmhook.fc", "$NS.gcashfix")

  val PRESETS = listOf("whole", "extract", "dpt", "fart")

  /** Preset override flags (null = use the preset default). */
  data class Opts(
      val rasp: Boolean = false,
      val dobby: Boolean = false,
      val extout: String? = null,
      val interpMs: String? = null,
      val workerDelay: String? = null,
      val predelay: String? = null,
  )

  data class Result(
      val preset: String,
      val target: String,
      val props: Map<String, String>,
      val warnings: List<String>,
      val dumpDir: String,
  )

  // ---- resetprop plumbing -----------------------------------------------------

  private val resetprop: String? by lazy {
    listOf(
            "/data/adb/ap/bin/resetprop",
            "/data/adb/magisk/resetprop",
            "/data/adb/ksu/bin/resetprop")
        .firstOrNull { runCatching { File(it).canExecute() }.getOrDefault(false) }
        ?: "resetprop" // fall back to PATH
  }

  private fun exec(vararg cmd: String): Boolean {
    return runCatching {
          val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
          val out = p.inputStream.bufferedReader().readText()
          val code = p.waitFor()
          if (code != 0) Log.w(TAG, "cmd failed (${code}): ${cmd.joinToString(" ")} -> $out")
          code == 0
        }
        .getOrElse {
          Log.e(TAG, "cmd threw: ${cmd.joinToString(" ")}", it)
          false
        }
  }

  private fun setProp(name: String, value: String) {
    val rp = resetprop ?: throw IllegalStateException("resetprop not found (APatch/Magisk/KernelSU)")
    if (!exec(rp, name, value))
        throw IllegalStateException("resetprop failed to set $name=$value (is the daemon rooted?)")
  }

  private fun delProp(name: String) {
    val rp = resetprop ?: return
    exec(rp, "--delete", name) // best-effort; deleting an unset prop is a no-op
  }

  private fun getProp(name: String): String = SystemProperties.get(name, "")

  private fun setT(k: String, v: String) = setProp("$NS.$k", v)

  private fun clearAll() {
    delProp(MASTER)
    delProp(TARGET)
    TUNING.forEach { delProp("$NS.$it") }
  }

  // ---- preset -> prop tables (mirror of tools/vunpack/vunpack) -----------------

  private fun applyShared(props: LinkedHashMap<String, String>, o: Opts) {
    if (o.dobby) { props["stealth"] = "0"; props["traceless"] = "0" }
    o.extout?.let { props["extout"] = it }
    o.interpMs?.let { props["interp_ms"] = it }
    o.workerDelay?.let { props["worker_delay_ms"] = it }
    o.predelay?.let { props["predelay_ms"] = it }
  }

  /** Build the tuning-prop set for a preset (does not touch the device). */
  private fun buildPreset(preset: String, o: Opts): LinkedHashMap<String, String> {
    val p = LinkedHashMap<String, String>()
    when (preset) {
      "whole" -> { // whole-dex encryption shell (Bangcle/SecNeo/百度/Yidun)
        p["dexfind"] = "1"
        if (o.rasp) p["traceless"] = "1"
        applyShared(p, o)
      }
      "extract" -> { // method-extraction shell that self-patches libart (51job)
        p["stealth"] = "0"
        p["traceless"] = "0"
        p["dexfind"] = "1"
        p["trigger"] = "1"
        p["worker_delay_ms"] = o.workerDelay ?: "12000"
        p["extout"] = o.extout ?: "1"
        o.interpMs?.let { p["interp_ms"] = it }
        o.predelay?.let { p["predelay_ms"] = it }
      }
      "dpt" -> { // per-class DefineClass-restore shell (dpt-shell)
        p["interp"] = "1"
        p["activeload"] = "1"
        p["extout"] = o.extout ?: "1"
        o.interpMs?.let { p["interp_ms"] = it }
        applyShared(p, o)
      }
      "fart" -> { // FART-style interpreter capture only
        p["interp"] = "1"
        p["extout"] = o.extout ?: "1"
        o.interpMs?.let { p["interp_ms"] = it }
        applyShared(p, o)
      }
      else -> throw IllegalArgumentException("unknown preset '$preset' (want: ${PRESETS.joinToString("|")})")
    }
    return p
  }

  // ---- public API -------------------------------------------------------------

  /** Arm [preset] for [pkg]: clear everything, set the master + target + preset props. */
  fun arm(preset: String, pkg: String, o: Opts): Result {
    if (pkg.isBlank()) throw IllegalArgumentException("package name required")
    val props = buildPreset(preset, o)

    clearAll()
    setProp(MASTER, "1")
    setProp(TARGET, pkg)
    props.forEach { (k, v) -> setT(k, v) }

    // validation (mirror vunpack validate) -- advisory; native fails safe.
    val warnings = mutableListOf<String>()
    if (props["trigger"] == "1" && props["dexfind"] != "1") {
      setT("dexfind", "1")
      props["dexfind"] = "1"
      warnings += "trigger=1 but dexfind!=1 -> auto-enabled dexfind (trigger has no dexes otherwise)"
    }
    val kpmEngaged = props["stealth"] == "1" || props["traceless"] == "1"
    val wd = props["worker_delay_ms"]?.toIntOrNull() ?: 0
    if (kpmEngaged && wd > 0) {
      warnings +=
          "KPM engaged (stealth/traceless) AND worker_delay set -- for a self-libart-patching shell use --dobby instead (KPM PTE-manage collides with the shell's libart writes)"
    }

    val dumpDir =
        if (props["extout"] == "1") "/storage/emulated/0/Android/data/$pkg/files/vunpack"
        else "/data/user/0/$pkg/unpack"
    return Result(preset, pkg, props, warnings, dumpDir)
  }

  /** Disarm: clear the master + target + all tuning props. Leaves EXTERNAL flags alone. */
  fun disarm() = clearAll()

  /** Set/delete a single NS.<key> (escape hatch). value == null deletes. */
  fun raw(key: String, value: String?) {
    if (value == null) delProp("$NS.$key") else setT(key, value)
  }

  /** Current prop state: master, target, any set tuning props, and the external flags. */
  fun status(): LinkedHashMap<String, String> {
    val m = LinkedHashMap<String, String>()
    m[MASTER] = getProp(MASTER).ifEmpty { "<unset>" }
    m[TARGET] = getProp(TARGET).ifEmpty { "<unset>" }
    TUNING.forEach { k ->
      val v = getProp("$NS.$k")
      if (v.isNotEmpty()) m["$NS.$k"] = v
    }
    EXTERNAL.forEach { k ->
      val v = getProp(k)
      if (v.isNotEmpty()) m["$k (external)"] = v
    }
    return m
  }
}
