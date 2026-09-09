# tools/vunpack — on-device front-end for the stealth-unpacker prop contract

`vunpack` is a small root shell script that drives the Vector stealth unpacker
(`native/src/unpack`) through its `persist.kpmhook.unpack.*` property contract. That
contract is a stable ABI (see `../../native/src/unpack/README.md`), but there are ~20
interacting props and a few mutual-exclusion rules that are easy to get wrong by hand.
`vunpack` encodes the README recipes as **named presets**, validates the combinations,
and writes the props coherently. **The native side is untouched** — this is pure
front-end over `resetprop`.

It is the terminal-side counterpart of the offline `../dexfixer/` reassembler:
`vunpack` arms the on-device capture; `dexfixer.py` splices the pulled dumps.

> The same preset → prop mapping is the canonical contract the Vector manager UI
> (daemon) reuses. If you change a preset here, mirror it there. Keep the
> `PRESET_*`/`TUNING` tables in `vunpack` authoritative.

## Install

```
adb push vunpack /data/local/tmp/vunpack
adb shell su -c 'chmod 755 /data/local/tmp/vunpack'
```

Root is required (it calls `resetprop`, auto-detected: APatch `/data/adb/ap/bin/resetprop`,
Magisk, KernelSU, or `resetprop` in `PATH`). Run everything under `su`:

```
adb shell su -c 'sh /data/local/tmp/vunpack <cmd> ...'
```

## Commands

| command | effect |
|---|---|
| `on <preset> <pkg> [opts]` | clear everything, then arm `<preset>` for `<pkg>` |
| `off` | disarm: clear the master + target + **all** tuning props |
| `status` | print the current prop state (read-only) |
| `log [seconds]` | tail logcat filtered to `[unpack]`/`[gcashfix]`/`[openat]` (default 60s) |
| `raw <key> [value]` | escape hatch: set `persist.kpmhook.unpack.<key>` (omit value = delete) |

Every `on`/`off` starts from a **cleared** state (`clear_all`), so no flag ever leaks
from one preset into the next. `off` touches only the props `vunpack` manages — it leaves
`persist.kpmhook.fc` / `.fshide` / `.l2` / `.gcash.*` / `.unpack.gcashfix` alone (those are
other features, shown in `status` as "external to preset").

## Presets

Each preset maps to a recipe in `native/src/unpack/README.md`:

| preset | packer class | props set |
|---|---|---|
| `whole` | whole-dex encryption shell (Bangcle / SecNeo / 百度加固 / Yidun) | `dexfind=1` (`+traceless=1` with `--rasp`) |
| `extract` | method-extraction shell that self-patches libart (51job `s.h.e.l.l`) | `stealth=0 traceless=0 dexfind=1 trigger=1 worker_delay_ms=12000 extout=1` |
| `dpt` | per-class `DefineClass`-restore shell (dpt-shell) | `interp=1 activeload=1 extout=1` |
| `fart` | FART-style interpreter capture only (side-cache shells) | `interp=1 extout=1` |

`whole` engages the KPM only with `--rasp` (traceless). `extract` is deliberately pure
Dobby: engaging the KPM would PTE-manage the target's libart pages and collide with the
shell's own libart patching (see `StartIfEnabled` in `unpacker.cpp`).

## Options

| option | applies to | effect |
|---|---|---|
| `--rasp` | `whole` | route the dexfind `FindClass` hook via KPM clone (`traceless=1`) — RASP-safe |
| `--dobby` | any | force pure Dobby (`stealth=0 traceless=0`); KPM not engaged |
| `--extout` / `--no-extout` | any | write dumps to the app EXTERNAL dir (pullable past strict SELinux MLS) |
| `--interp-ms <N>` | `dpt` / `fart` | interpreter capture window (default 30000) |
| `--worker-delay <N>` | any | sleep before the worker's first ART touch (`extract` default 12000) |
| `--predelay <N>` | any | dexfind: wait before the `FindClass` hook (default 6000) |

## Validation

`vunpack` re-reads what it set and warns on the documented hazards:

- `trigger=1` without `dexfind` → auto-enables `dexfind` (the per-method `GetCodeItem`
  restore has no dexes to walk otherwise).
- KPM engaged (`stealth`/`traceless`) **and** a non-zero `worker_delay` → warns that a
  self-libart-patching shell wants `--dobby` instead (KPM PTE-manage collides with the
  shell's libart writes).

These are advisory; the native side already fails safe.

## Output & pulling

Dumps land in:

- default: `/data/user/0/<pkg>/unpack`
- `extout=1`: `/storage/emulated/0/Android/data/<pkg>/files/vunpack` — root reads the same
  bytes at `/data/media/0/Android/data/<pkg>/files/vunpack`, so `adb pull` works even under
  a hardened app's SELinux MLS categories.

Then run the offline reassembler in `../dexfixer/`.

## Examples

```
# whole-dex encryption shell
vunpack on whole com.some.app
# ... same, but the app RASP-scans libart:
vunpack on whole com.some.app --rasp

# 51job-style method-extraction shell (self-patches libart)
vunpack on extract com.job.android

# FART interpreter capture, longer window
vunpack on fart com.some.app --interp-ms 45000

vunpack status          # what's armed right now
vunpack log 90          # watch progress for 90s
vunpack off             # ALWAYS run when done
```

## Safety

- The props are `persist.` — an armed unpack **survives reboot**. Always `vunpack off`
  when finished.
- On a shared/production device, `status` first: `on` overwrites `persist.kpmhook.target`,
  so it would clobber any unpack already armed for another app. `vunpack` never touches
  existing KPM slots — arming only sets props; the worker still self-gates on
  `target == process nice-name`, so an un-installed / non-matching target is inert.
- `<pkg>` is the process **nice name**. For the main process that equals the package name;
  for an app whose target work runs in a `:process`, pass that process name instead.
