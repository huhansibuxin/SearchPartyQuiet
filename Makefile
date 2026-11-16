# SearchPartyQuiet v1.0.1 - single auth-GOT rebind of _sqlite3_step in
#   searchpartyd (roothide only, starting 2026-11-16 per 老板)
# THEOS_PACKAGE_SCHEME is overridden by CI per matrix job; the ?= below is
# only the local default (never use '=' here).
export TARGET = iphone:clang:latest:16.0
export ARCHS = arm64e

THEOS_PACKAGE_SCHEME ?= roothide
export THEOS_PACKAGE_SCHEME
export _THEOS_PLATFORM_DPKG_DEB_COMPRESSION = gzip

TWEAK_NAME = SearchPartyQuiet
SearchPartyQuiet_FILES = Tweak.xm

# ZERO substrate/ellekit LINK dependency. searchpartyd is a launchd daemon:
# a dylib referencing libellekit can fail to dlopen silently. We use only
# __attribute__((constructor)), mach vm_protect and ptrauth builtins - no
# Logos, no inline-patch API. libsqlite3 is linked ONLY for sqlite3_sql()
# (a plain read of the statement's SQL text); it does not go through the
# rebound slot. No Foundation / UIKit. arm64e is REQUIRED (ptrauth builtins).
SearchPartyQuiet_LDFLAGS = -Wl,-dead_strip_dylibs -lsqlite3
SearchPartyQuiet_CFLAGS = -Os

# v1.0.5 dual flavor: LOG keeps on-disk logging, CLEAN (default) compiles it out.
# CI passes SPQ_FLAVOR=log|clean; hook/PAC/guard logic is IDENTICAL in both.
ifeq ($(SPQ_FLAVOR),log)
SearchPartyQuiet_CFLAGS += -DSPQ_NO_LOG=0
else
SearchPartyQuiet_CFLAGS += -DSPQ_NO_LOG=1
endif
ERROR_ON_WARNINGS = 0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
