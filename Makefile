LIB_NAME ?= libhmac

PROJ_FILES = ../../
LIB_FULL_NAME = $(LIB_NAME).a

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/libs/$(LIB_NAME)

CFLAGS += $(LIBS_CFLAGS)
CFLAGS += -ffreestanding -fpie -ffunction-sections -fdata-sections
CFLAGS += -I../../externals/libecc/src
CFLAGS += -I$(PROJ_FILES)/include/generated -I. -Iarch/cores/$(CONFIG_ARCH) -I$(PROJ_FILES)
CFLAGS += -MMD -MP -DWITH_LIBECC_CONFIG_OVERRIDE -DWITH_CURVE_FRP256V1 -DWITH_HASH_SHA256 -DWITH_SIG_ECDSA
CFLAGS += -MMD -MP -Os

# Add the libecc specific CFLAGS
CFLAGS += $(LIBSIGN_CFLAGS)


LDFLAGS += -fno-builtin -nostdlib -nostartfiles
LD_LIBS += -lsign -L$(BUILD_DIR)

BUILD_DIR ?= $(PROJ_FILE)build

SRC_DIR = .
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

OUT_DIRS = $(dir $(OBJ)) $(dir $(ARCH_OBJ))

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(ARCH_OBJ) $(OBJ)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

default: all

all: $(APP_BUILD_DIR) lib

show:
	@echo
	@echo "\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\tSRC_DIR\t\t=> " $(SRC_DIR)
	@echo "\tSRC\t\t=> " $(SRC)
	@echo "\tOBJ\t\t=> " $(OBJ)
	@echo

lib: $(APP_BUILD_DIR)/$(LIB_FULL_NAME)

#############################################################
# build targets (driver, core, SoC, Board... and local)
# App C sources files
$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

# lib
$(APP_BUILD_DIR)/$(LIB_FULL_NAME): $(OBJ)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
-include $(DRVDEP)
-include $(TESTSDEP)
