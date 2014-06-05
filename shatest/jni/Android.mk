LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	shatest.cpp

LOCAL_LDLIBS := -L$(LOCAL_PATH) -lssl -lcrypto

LOCAL_MODULE:= shatest

LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/external/openssl/include

include $(BUILD_EXECUTABLE)
