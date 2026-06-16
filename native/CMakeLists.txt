cmake_minimum_required(VERSION 3.10)

project(native)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(${VECTOR_ROOT}/external external)

file(GLOB_RECURSE NATIVE_SOURCES "src/*.cpp")

# Stealth-hook backend (vendored from ../../stealth-poc/lib): the libdbi AArch64
# recompiler + the kpmhook glue that maps LSPlant's inline_hooker/unhooker onto our
# KernelPatch module over the no-superkey syscall bridge. Plain C, so not matched by
# the *.cpp glob above -- list it explicitly (compiled as C, C linkage via kpmhook.h).
file(GLOB KPM_BACKEND_SOURCES "src/kpm/*.c")

add_library(${PROJECT_NAME} STATIC ${NATIVE_SOURCES} ${KPM_BACKEND_SOURCES})

set(IGNORED_WARNINGS
    -Wno-c99-extensions
    -Wno-extra-semi
    -Wno-gnu-flexible-array-initializer
    -Wno-gnu-string-literal-operator-template
    -Wno-gnu-zero-variadic-macro-arguments
    -Wno-variadic-macros
    -Wno-zero-length-array
)

# --- Include Directories ---
# Add the 'include' directory as a PUBLIC include path. This means any
# target that links against vector_native will also inherit this include path.
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Add the 'src' directory and external XZ library includes as PRIVATE.
# These are only needed to build vector_native itself.
target_include_directories(${PROJECT_NAME} PRIVATE src ${VECTOR_ROOT}/external/xz-embedded/linux/include)

# --- Compiler Options ---
# Apply the standard pedantic warnings and the ignored warnings list.
target_compile_options(${PROJECT_NAME} PRIVATE -Wpedantic ${IGNORED_WARNINGS})

# Compile the stealth unpacker (native/src/unpack/*). Those TUs are #ifdef-guarded on this
# macro; without it they are empty. The feature stays dormant at runtime until
# persist.kpmhook.unpack=1 (same prop-gate discipline as fc/l2/probe).
target_compile_definitions(${PROJECT_NAME} PRIVATE VECTOR_UNPACK_ENABLED)

# --- Library Linking ---
# Link against required external and system libraries.
# PUBLIC libraries are propagated to targets that link against this one.
# PRIVATE libraries are only used for the compilation of this target.
target_link_libraries(${PROJECT_NAME} PUBLIC
    dobby_static
    lsplant_static
    xz_static
    log # Android logging library
    fmt-header-only
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    dex_builder_static
)
