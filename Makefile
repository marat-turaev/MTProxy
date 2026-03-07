OBJ	=	objs
DEP	=	dep
EXE = ${OBJ}/bin

# If COMMIT is provided on the command line (e.g. deploy scripts using rsync
# without .git), don't try to call git here.
COMMIT ?= $(shell git log -1 --pretty=format:"%H" 2>/dev/null || echo unknown)

ARCH =
ifeq ($m, 32)
ARCH = -m32
endif
ifeq ($m, 64)
ARCH = -m64
endif

HOST_ARCH := $(shell uname -m 2>/dev/null)
HOST_OS := $(shell uname -s 2>/dev/null)

SIMD_CFLAGS =
ifneq ($(filter x86_64 amd64 i386 i686,$(HOST_ARCH)),)
SIMD_CFLAGS += -mpclmul -mssse3 -mfpmath=sse
endif

LTO_CFLAGS =
LTO_LDFLAGS =
GC_SECTIONS_LDFLAGS =
HARDEN_CFLAGS =
HARDEN_LDFLAGS =
ifeq ($(HOST_OS),Linux)
LTO_CFLAGS += -flto=auto
LTO_LDFLAGS += -flto=auto
GC_SECTIONS_LDFLAGS += -Wl,--gc-sections
HARDEN_CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
HARDEN_LDFLAGS += -pie -Wl,-z,relro,-z,now
endif

CFLAGS = $(ARCH) -O3 -std=gnu11 -Wall -Wno-array-bounds -march=native -ffunction-sections -fdata-sections $(SIMD_CFLAGS) $(LTO_CFLAGS) $(HARDEN_CFLAGS) -fno-strict-aliasing -fno-strict-overflow -fwrapv -DAES=1 -DCOMMIT=\"${COMMIT}\" -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
LDFLAGS = $(ARCH) -ggdb $(LTO_LDFLAGS) $(GC_SECTIONS_LDFLAGS) $(HARDEN_LDFLAGS) -lm -lrt -lcrypto -lz -lpthread

LIB = ${OBJ}/lib
CINCLUDE = -iquote common -iquote .

LIBLIST = ${LIB}/libkdb.a

PROJECTS = common jobs mtproto net crypto engine tests

OBJDIRS := ${OBJ} $(addprefix ${OBJ}/,${PROJECTS}) ${EXE} ${LIB}
DEPDIRS := ${DEP} $(addprefix ${DEP}/,${PROJECTS})
ALLDIRS := ${DEPDIRS} ${OBJDIRS}


.PHONY:	all clean sanitize tsan

EXELIST	:= ${EXE}/mtproto-proxy ${EXE}/fake_tls_startup_test


OBJECTS	=	\
  ${OBJ}/mtproto/mtproto-proxy.o ${OBJ}/mtproto/mtproto-config.o ${OBJ}/net/net-tcp-rpc-ext-server.o

TEST_OBJECTS = ${OBJ}/tests/fake_tls_startup_test.o

DEPENDENCE_CXX		:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS_CXX}))
DEPENDENCE_STRANGE	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS_STRANGE}))
DEPENDENCE_NORM	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS}))

LIB_OBJS_NORMAL := \
	${OBJ}/common/crc32c.o \
	${OBJ}/common/pid.o \
	${OBJ}/common/sha1.o \
	${OBJ}/common/sha256.o \
	${OBJ}/common/md5.o \
	${OBJ}/common/resolver.o \
	${OBJ}/common/parse-config.o \
	${OBJ}/crypto/aesni256.o \
	${OBJ}/jobs/jobs.o ${OBJ}/common/mp-queue.o \
	${OBJ}/net/net-events.o ${OBJ}/net/net-msg.o ${OBJ}/net/net-msg-buffers.o \
	${OBJ}/net/net-config.o ${OBJ}/net/net-crypto-aes.o ${OBJ}/net/net-crypto-dh.o ${OBJ}/net/net-timers.o \
	${OBJ}/net/net-connections.o \
	${OBJ}/net/net-rpc-targets.o \
	${OBJ}/net/net-tcp-connections.o ${OBJ}/net/net-tcp-rpc-common.o ${OBJ}/net/net-tcp-rpc-client.o ${OBJ}/net/net-tcp-rpc-server.o \
	${OBJ}/net/net-http-server.o \
	${OBJ}/common/tl-parse.o ${OBJ}/common/common-stats.o \
	${OBJ}/engine/engine.o ${OBJ}/engine/engine-signals.o \
	${OBJ}/engine/engine-net.o \
	${OBJ}/engine/engine-rpc.o \
	${OBJ}/engine/engine-rpc-common.o \
	${OBJ}/net/net-thread.o ${OBJ}/net/net-stats.o ${OBJ}/common/proc-stat.o \
	${OBJ}/common/kprintf.o \
	${OBJ}/common/precise-time.o ${OBJ}/common/cpuid.o \
	${OBJ}/common/server-functions.o ${OBJ}/common/crc32.o \

LIB_OBJS := ${LIB_OBJS_NORMAL}

DEPENDENCE_LIB	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${LIB_OBJS}))

DEPENDENCE_ALL		:=	${DEPENDENCE_NORM} ${DEPENDENCE_STRANGE} ${DEPENDENCE_LIB}

OBJECTS_ALL		:=	${OBJECTS} ${LIB_OBJS}

all:	${ALLDIRS} ${EXELIST} 
dirs: ${ALLDIRS}
create_dirs_and_headers: ${ALLDIRS} 

${ALLDIRS}:	
	@test -d $@ || mkdir -p $@

-include ${DEPENDENCE_ALL}

${OBJECTS}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${TEST_OBJECTS}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${LIB_OBJS_NORMAL}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} -fpic ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${EXELIST}: ${LIBLIST}

${EXE}/mtproto-proxy:	${OBJ}/mtproto/mtproto-proxy.o ${OBJ}/mtproto/mtproto-config.o ${OBJ}/net/net-tcp-rpc-ext-server.o
	${CC} -o $@ $^ ${LIB}/libkdb.a ${LDFLAGS}

${EXE}/fake_tls_startup_test: ${TEST_OBJECTS} ${OBJ}/net/net-tcp-rpc-ext-server.o
	${CC} -o $@ $^ ${LIB}/libkdb.a ${LDFLAGS}

${LIB}/libkdb.a: ${LIB_OBJS}
	rm -f $@ && ar rcs $@ $^

clean:
	rm -rf ${OBJ} ${DEP} ${EXE} || true

force-clean: clean

sanitize:
	@$(MAKE) clean
	@$(MAKE) CFLAGS='$(CFLAGS) -O1 -g -fno-omit-frame-pointer -fno-lto -fsanitize=address,undefined' \
	  LDFLAGS='$(LDFLAGS) -fno-lto -fsanitize=address,undefined' all

tsan:
	@$(MAKE) clean
	@$(MAKE) CFLAGS='$(CFLAGS) -O1 -g -fno-omit-frame-pointer -fno-lto -fsanitize=thread' \
	  LDFLAGS='$(LDFLAGS) -fno-lto -fsanitize=thread' all
