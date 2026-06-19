# CC3 SuperLoader project makefile
#
# Put your main 6809 source file in PROGRAM_ASM, then run:
#
#   make
#
# This makefile only assembles your program.  It uses the prebuilt loader files
# in CC3x0_Loader:
#
#   CC3X0.BIN           streaming decompressor loaded by START.BAS
#   MOVER_TEMPLATE.BIN  generic mover patched by CC3_Comp into MOVER.BIN
#   START.BAS           Disk BASIC loader program
#   CC3_Comp            compiled compressor/packer

PROJECT      ?= MYGAME
PROGRAM_ASM  ?= main.asm
BUILD_DIR    ?= build
LOADER_DIR   ?= CC3x0_Loader
DISK_PREFIX  ?= DISK
COMP_OPTIONS ?= "-M812"

LWASM    ?= ./lwasm
DECB     ?= ./decb

ifeq ($(OS),Windows_NT)
CC3_COMP ?= CC3_Comp.exe
else
CC3_COMP ?= CC3_Comp
endif

ifneq ($(wildcard $(DECB)),)
DECB_RUN := $(abspath $(DECB))
else
DECB_RUN := $(DECB)
endif

PROGRAM_BIN := $(PROJECT).BIN
BUILD_ABS := $(abspath $(BUILD_DIR))

.PHONY: all mame xroar build disks clean

all: disks

mame: disks
	mame -nothrottle -debug -window -r 1280x800 coco3 -ramsize 2M -ext multi -ext:multi:slot2 ccpsg -ext:multi:slot3 orch90 -ext:multi:slot4 fdc -flop1 ./DISK1.DSK -printout "$(BUILD_DIR)"/PrinterFile.txt -frameskip 0 -autoboot_command "\n\n\n\nRUN\"START\n" -ui_active -skip_gameinfo -natural

xroar:	disks
	xroar -machine coco3h -ram 2048 -ratelimit -tv-input rgb -kbd-translate -load-fd0 ./DISK1.DSK

build:
	mkdir -p "$(BUILD_DIR)"
	cp "$(LOADER_DIR)/START.BAS" "$(BUILD_DIR)/START.BAS"
	cp "$(LOADER_DIR)/CC3X0.BIN" "$(BUILD_DIR)/CC3X0.BIN"
	cp "$(LOADER_DIR)/MOVER_TEMPLATE.BIN" "$(BUILD_DIR)/MOVER_TEMPLATE.BIN"
	"$(LWASM)" -9bl -p cd -o"$(BUILD_DIR)/$(PROGRAM_BIN)" "$(PROGRAM_ASM)" > "$(BUILD_DIR)/$(PROJECT)_Listing.txt" -i
	cp "$(BUILD_DIR)/$(PROGRAM_BIN)" "$(LOADER_DIR)/$(PROGRAM_BIN)"
	cd "$(LOADER_DIR)" && "./$(CC3_COMP)" "$(PROGRAM_BIN)" -o"$(PROJECT)" $(COMP_OPTIONS)
	cp "$(LOADER_DIR)/MOVER.BIN" "$(BUILD_DIR)/MOVER.BIN"
	cp "$(LOADER_DIR)/$(PROJECT).CC3X0" "$(BUILD_DIR)/$(PROJECT).CC3X0"
	cp "$(LOADER_DIR)/$(PROJECT)_Report.txt" "$(BUILD_DIR)/$(PROJECT)_Report.txt"
	cp "$(LOADER_DIR)/STREAMFILES.LST" "$(BUILD_DIR)/STREAMFILES.LST"
	cp "$(LOADER_DIR)/DISKFILES.LST" "$(BUILD_DIR)/DISKFILES.LST"
	cd "$(LOADER_DIR)" && while IFS=, read disk f; do \
		if [ -z "$$disk" ]; then continue; fi; \
		cp "$$f" "$(BUILD_ABS)/$$f"; \
	done < DISKFILES.LST

disks: build
	"$(DECB_RUN)" dskini "$(DISK_PREFIX)1.DSK"
	"$(DECB_RUN)" copy -0 -a -t -l -r "$(BUILD_DIR)/START.BAS" "$(DISK_PREFIX)1.DSK",START.BAS
	"$(DECB_RUN)" copy -2 -b -r "$(BUILD_DIR)/MOVER.BIN" "$(DISK_PREFIX)1.DSK",MOVER.BIN
	"$(DECB_RUN)" copy -2 -b -r "$(BUILD_DIR)/CC3X0.BIN" "$(DISK_PREFIX)1.DSK",CC3X0.BIN
	cd "$(BUILD_DIR)" && last=1; while IFS=, read disk f; do \
		if [ -z "$$disk" ]; then continue; fi; \
		dsk="../$(DISK_PREFIX)$${disk}.DSK"; \
		if [ "$$disk" != "$$last" ]; then \
			"$(DECB_RUN)" dskini "$$dsk"; \
			last="$$disk"; \
		fi; \
		"$(DECB_RUN)" copy -2 -b -r "$$f" "$$dsk","$$f"; \
	done < DISKFILES.LST

clean:
	rm -rf "$(BUILD_DIR)" "$(DISK_PREFIX)"*.DSK
	cd "$(LOADER_DIR)" && rm -f "$(PROGRAM_BIN)" "$(PROJECT).CC3X0" "$(PROJECT)_Report.txt" MOVER.BIN COMP*.BIN STREAMFILES.LST DISKFILES.LST
