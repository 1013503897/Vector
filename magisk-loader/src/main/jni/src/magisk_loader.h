/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

//
// Created by Nullptr on 2022/3/16.
//

#pragma once

#include "../src/native_api.h"
#include "context.h"
#include "elf_util.h"
#include "symbol_cache.h"

namespace lspd {
class MagiskLoader : public Context {
public:
    inline static void Init() { instance_ = std::make_unique<MagiskLoader>(); }

    inline static MagiskLoader *GetInstance() {
        return static_cast<MagiskLoader *>(instance_.get());
    }

    void OnNativeForkAndSpecializePre(JNIEnv *env, jint uid, jintArray &gids, jstring &nice_name,
                                      jboolean is_child_zygote, jstring app_data_dir);

    void OnNativeForkAndSpecializePost(JNIEnv *env, jstring nice_name, jstring app_dir);

    void OnNativeForkSystemServerPre(JNIEnv *env);

    void OnNativeForkSystemServerPost(JNIEnv *env);

protected:
    void LoadDex(JNIEnv *env, PreloadedDex &&dex) override;

    void SetupEntryClass(JNIEnv *env) override;

private:
    bool skip_ = false;
    const lsplant::InitInfo initInfo = lsplant::InitInfo{
        .inline_hooker =
            [](auto t, auto r) {
                void *bk = nullptr;
                return HookInline(t, r, &bk) == 0 ? bk : nullptr;
            },
        .inline_unhooker = [](auto t) { return UnhookInline(t) == 0; },
        .art_symbol_resolver = [](auto symbol) { return GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return GetArt()->getSymbPrefixFirstAddress(symbol); },
    };

    static void setAllowUnload(bool unload);
};

struct MapInfo {
    /// \brief The start address of the memory region.
    uintptr_t start;
    /// \brief The end address of the memory region.
    uintptr_t end;
    /// \brief The permissions of the memory region. This is a bit mask of the following values:
    /// - PROT_READ
    /// - PROT_WRITE
    /// - PROT_EXEC
    uint8_t perms;
    /// \brief Whether the memory region is private.
    bool is_private;
    /// \brief The offset of the memory region.
    uintptr_t offset;
    /// \brief The device number of the memory region.
    /// Major can be obtained by #major()
    /// Minor can be obtained by #minor()
    dev_t dev;
    /// \brief The inode number of the memory region.
    ino_t inode;
    /// \brief The path of the memory region.
    std::string path;

    /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
    /// This is useful to find out the inode of the library to hook.
    /// \param[in] pid The process id to scan. This is "self" by default.
    /// \return A list of \ref MapInfo entries.
    static std::vector<MapInfo> Scan(std::string_view pid = "self");
};
}  // namespace lspd
