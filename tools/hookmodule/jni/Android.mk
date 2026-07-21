LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := vechook
LOCAL_SRC_FILES := vechook.cpp
LOCAL_CPPFLAGS  := -std=c++20 -fvisibility=hidden -Wall
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
