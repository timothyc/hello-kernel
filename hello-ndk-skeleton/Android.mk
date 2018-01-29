# https://developer.android.com/ndk/guides/android_mk.html
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := hello-ndk-skeleton.out
#LOCAL_C_INCLUDE :=
LOCAL_SRC_FILES := \
	hello-ndk-skeleton.cpp
include $(BUILD_EXECUTABLE)
