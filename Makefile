export GO ?= go
export CGO_ENABLED = 0

TAG := $(shell git describe --always --tags $(git rev-list --tags --max-count=1) --match v*)
LDFLAGS := -s -w -X 'main.version=${TAG}'

.PHONY: all
all: wireproxy

.PHONY: wireproxy
wireproxy:
	${GO} build -trimpath -ldflags "${LDFLAGS}" ./cmd/wireproxy

# --- Android ---------------------------------------------------------------
#
# Built for Homerun's Android host, which ships wireproxy inside the APK and
# execs it. Two things make these targets different from the ones above.
#
# GOOS=android, not GOOS=linux. A linux/arm64 PIE binary builds fine and then
# will not start on a phone: Go stamps PT_INTERP as /lib/ld-linux-aarch64.so.1,
# a glibc path that does not exist under bionic. GOOS=android emits
# /system/bin/linker64 and is PIE by default, which API 21+ requires for exec.
#
# arm64 needs no NDK — Go links it internally with cgo off. amd64 does:
# `android/amd64 requires external (cgo) linking`. Since amd64 exists only for
# the emulator, that asymmetry costs nothing on the shipping path.
#
# The output is named lib*.so because Android's packager only puts files
# matching that pattern into nativeLibraryDir, which since API 29 is the only
# directory an app may exec from. It is an executable, not a library.

ANDROID_OUT ?= dist/android

.PHONY: android
android: android-arm64 android-amd64

.PHONY: android-arm64
android-arm64:
	mkdir -p ${ANDROID_OUT}/arm64-v8a
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 ${GO} build -trimpath \
		-ldflags "${LDFLAGS}" \
		-o ${ANDROID_OUT}/arm64-v8a/libwireproxy.so ./cmd/wireproxy

# Emulator only. Needs ANDROID_NDK_HOME and a host-matching prebuilt, e.g.
#   make android-amd64 \
#     CC=$$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android26-clang
.PHONY: android-amd64
android-amd64:
	@test -n "${CC}" || { \
		echo "android-amd64 needs CC set to an NDK clang (see the Makefile comment)"; \
		exit 1; \
	}
	mkdir -p ${ANDROID_OUT}/x86_64
	CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC=${CC} ${GO} build -trimpath \
		-ldflags "${LDFLAGS}" \
		-o ${ANDROID_OUT}/x86_64/libwireproxy.so ./cmd/wireproxy

.PHONY: clean
clean:
	${RM} wireproxy
	${RM} -r ${ANDROID_OUT}
