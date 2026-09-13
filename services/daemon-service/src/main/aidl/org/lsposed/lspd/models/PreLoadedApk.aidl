package org.lsposed.lspd.models;

parcelable PreLoadedApk {
    List<SharedMemory> preLoadedDexes;
    List<String> moduleClassNames;
    List<String> moduleLibraryNames;
    boolean legacy;
    // Where the daemon staged this module's native libraries, for the one process that cannot map
    // them out of the APK. Null when the module ships none for this ABI, when staging failed, or
    // when the module was never destined for system_server in the first place.
    @nullable String nativeLibraryDir;
}
