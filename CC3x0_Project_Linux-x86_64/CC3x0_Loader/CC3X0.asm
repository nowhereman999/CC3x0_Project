* CC3_NewLoaderCode3.asm
*
* Streaming 6809 decoder for CC3_Comp.bas CC3X03 packet streams.
*
* BASIC-driven load sequence:
*
*   PCLEAR 1
*   CLEAR 200,&H1EFF
*   LOADM "MOVER.BIN"
*   EXEC &H130E          ; map scratch source block, move stack, enter ROM mode
*   LOADM "CC3X0.BIN"
*   LOADM "COMP0000.BIN": EXEC &H0F00
*   LOADM "COMP0001.BIN": EXEC &H0F00
*   ...
*   final COMP####.BIN:  EXEC &H1311
*
* Each COMP####.BIN file is a normal LOADM file.  It loads up to 8192 stream
* bytes at $2000-$3FFF, then loads:
*
*   $0F04-$0F05  current chunk byte count
*   $0F06        flags, bit 0 means "ask for next disk before continuing"
*                       bit 1 means "run final MOVER before decoding"
*
* The decompressor stores a status byte at $0F03 before it returns to BASIC:
*
*   0    load the next COMP####.BIN from the current disk
*   1    ask the user for the next disk, then load the next COMP####.BIN
*   255  stream/decode error
*
* The compressor cuts COMP####.BIN files only between complete packet records.
* That keeps this decoder simple: it never has to suspend halfway through an
* Elias bitstream or halfway through a copy command.
*
* BASIC/DOS runs in ROM mode between chunks, but the decoder switches to RAM
* mode while it is actually expanding data.  That lets packets targeting
* physical blocks $3C-$3F update RAM through the $4000-$5FFF destination
* window.  ReturnToBasic switches back to ROM mode before Disk BASIC runs again.

SOURCE_WINDOW           EQU     $2000
SOURCE_END              EQU     $4000
DEST_WINDOW             EQU     $4000
COPY_WINDOW             EQU     $6000
DECOMP_PROGRESS_ADDR    EQU     $05E0
DECOMP_PROGRESS_STEPS   EQU     26
DECOMP_BAR_CELLS        EQU     13
STREAM_CHUNK_NEXT_DISK  EQU     1
BASIC_BANK2             EQU     $3A
BASIC_BANK3             EQU     $3B
REGULAR_SPEED           EQU     $FFD8
HIGH_SPEED_MODE         EQU     $FFD9
ROM_MODE_ENABLE         EQU     $FFDE
RAM_MODE_ENABLE         EQU     $FFDF

    ORG     $0F00
    SETDP   $0F

    JMP     StreamEntry

* Public control bytes used by the BASIC loader.
StreamStatus            FCB     0       * $0F03
ChunkLength             FDB     0       * $0F04-$0F05
ChunkFlags              FCB     0       * $0F06

* Persistent decoder state.  CC3X0.BIN initializes these once; subsequent
* COMP####.BIN files only overwrite ChunkLength and ChunkFlags.
Started                 FCB     0
SavedCC                 FCB     0
EntryStack              FDB     0
PacketCount             FDB     0
PacketTotal             FDB     0
ExecAddr                FDB     0
FinalJumpAddr           FDB     0
UserMMUBlocks           FCB     0,0,0,0,0,0,0,0
UserMMUBlocks1          FCB     0,0,0,0,0,0,0,0
HeaderLoadBlock         FCB     0
HeaderDecodeBlock       FCB     0
ShadowCount             FCB     0
ShadowPairs             FCB     0,0,0,0,0,0,0,0,0,0
InputPtr                FDB     0
ChunkEnd                FDB     0
BitControl              FCB     0
BitMask                 FCB     0
DestBlock               FCB     0
DestPtr                 FDB     0
OutRemaining            FDB     0
RunLength               FDB     0
LastCopyBlock           FCB     0
LastCopyOffset          FDB     0
TempByte                FCB     0
TempWord                FDB     0
ProgressBarSize         FCB     0
ProgressBarRemainder    FDB     0
ProgressPercent         FCB     0
ProgressPercentRemainder FDB    0

StreamEntry:
    LDA     #$0F
    TFR     A,DP
    STS     <EntryStack
    TFR     CC,A
    STA     <SavedCC
    ORCC    #$50
    STA     HIGH_SPEED_MODE
    STA     RAM_MODE_ENABLE

    LDD     <ChunkLength
    BEQ     StreamError
    ADDD    #SOURCE_WINDOW
    STD     <ChunkEnd
    LDX     #SOURCE_WINDOW
    STX     <InputPtr

    LDA     <Started
    BNE     PrepareStartedChunk

    CLR     <BitMask
    JSR     ReadHeader
    JSR     PrepareDecodeSource
    LDA     #1
    STA     <Started
    JSR     InitDecompressProgress
    BRA     DecodeChunkLoop

PrepareStartedChunk:
    JSR     PrepareDecodeSource

DecodeChunkLoop:
    LDD     <PacketCount
    BNE     DecodeNextPacket
    JMP     RestoreAndLaunch

DecodeNextPacket:
    LDX     <InputPtr
    CMPX    <ChunkEnd
    BHS     NeedNextChunk

    SUBD    #1
    STD     <PacketCount
    JSR     ReadPacketHeader
    JSR     DecodePacketBody
    JSR     AdvanceDecompressProgress
    BRA     DecodeChunkLoop

NeedNextChunk:
    LDA     <ChunkFlags
    ANDA    #STREAM_CHUNK_NEXT_DISK
    BEQ     NeedSameDisk
    LDA     #1
    BRA     StoreStreamStatus
NeedSameDisk:
    CLRA
StoreStreamStatus:
    STA     <StreamStatus
    BRA     ReturnToBasic

StreamError:
    LDS     <EntryStack
    LDA     #255
    STA     <StreamStatus
    BRA     ReturnToBasic

ReturnToBasic:
    LDA     <HeaderLoadBlock
    STA     $FFA1
    LDA     #BASIC_BANK2
    STA     $FFA2
    LDA     #BASIC_BANK3
    STA     $FFA3
    STA     REGULAR_SPEED
    STA     ROM_MODE_ENABLE
    LDA     <SavedCC
    PSHS    A
    CLRA
    TFR     A,DP
    PULS    A
    TFR     A,CC
    RTS

ReadHeader:
    JSR     ReadByte
    CMPA    #$43            * C
    BNE     StreamError
    JSR     ReadByte
    CMPA    #$43            * C
    BNE     StreamError
    JSR     ReadByte
    CMPA    #$33            * 3
    BNE     StreamError
    JSR     ReadByte
    CMPA    #$58            * X
    BNE     StreamError
    JSR     ReadByte
    CMPA    #$30            * 0
    BNE     StreamError
    JSR     ReadByte
    CMPA    #$33            * 3
    BNE     StreamError

    JSR     ReadWord
    STD     <PacketCount
    STD     <PacketTotal
    JSR     ReadWord
    STD     <ExecAddr

    LDU     #UserMMUBlocks
    LDB     #8
ReadUserMMU0:
    JSR     ReadByte
    STA     ,U+
    DECB
    BNE     ReadUserMMU0

    LDU     #UserMMUBlocks1
    LDB     #8
ReadUserMMU1:
    JSR     ReadByte
    STA     ,U+
    DECB
    BNE     ReadUserMMU1

    JSR     ReadByte
    STA     <HeaderLoadBlock
    JSR     ReadByte
    STA     <HeaderDecodeBlock
    JSR     ReadByte
* Reserved header byte.
    JSR     ReadByte
* Reserved header byte.
    JSR     ReadByte
    STA     <ShadowCount

    LDU     #ShadowPairs
    LDB     #10
ReadShadowPairs:
    JSR     ReadByte
    STA     ,U+
    DECB
    BNE     ReadShadowPairs

    JSR     ReadWord
    STD     <FinalJumpAddr
    RTS

PrepareDecodeSource:
    LDA     <HeaderLoadBlock
    CMPA    <HeaderDecodeBlock
    BEQ     MapDecodeSource

* Disk BASIC may have loaded this chunk into a ROM-mode-writable borrowed
* block.  Copy it to the real decoder source block now that RAM mode is active.
    STA     $FFA1
    LDA     <HeaderDecodeBlock
    STA     $FFA2
    LDX     #SOURCE_WINDOW
    LDU     #DEST_WINDOW
    LDY     #$2000
CopyLoadedChunk:
    LDA     ,X+
    STA     ,U+
    LEAY    -1,Y
    BNE     CopyLoadedChunk

MapDecodeSource:
    LDA     <HeaderDecodeBlock
    STA     $FFA1
    RTS

InitDecompressProgress:
    CLR     <ProgressBarSize
    CLR     <ProgressBarRemainder
    CLR     <ProgressBarRemainder+1
    CLR     <ProgressPercent
    CLR     <ProgressPercentRemainder
    CLR     <ProgressPercentRemainder+1
    JSR     DrawDecompressProgress
    RTS

AdvanceDecompressProgress:
    LDD     <ProgressBarRemainder
    ADDD    #DECOMP_PROGRESS_STEPS
AdvanceBarLoop:
    CMPD    <PacketTotal
    BLO     StoreBarRemainder
    SUBD    <PacketTotal
    INC     <ProgressBarSize
    BRA     AdvanceBarLoop
StoreBarRemainder:
    STD     <ProgressBarRemainder

    LDD     <ProgressPercentRemainder
    ADDD    #100
AdvancePercentLoop:
    CMPD    <PacketTotal
    BLO     StorePercentRemainder
    SUBD    <PacketTotal
    INC     <ProgressPercent
    BRA     AdvancePercentLoop
StorePercentRemainder:
    STD     <ProgressPercentRemainder

    JSR     DrawDecompressProgress
    RTS

DrawDecompressProgress:
    LDX     #DecompressText
    LDU     #DECOMP_PROGRESS_ADDR
    LDB     #14
DrawDecompressPrefix:
    LDA     ,X+
    STA     ,U+
    DECB
    BNE     DrawDecompressPrefix

    LDA     <ProgressBarSize
    STA     <TempByte
    LDB     #DECOMP_BAR_CELLS
DrawDecompressBar:
    LDA     <TempByte
    CMPA    #2
    BLO     DrawDecompressHalf
    SUBA    #2
    STA     <TempByte
    LDA     #$AF
    BRA     StoreDecompressBar
DrawDecompressHalf:
    TSTA
    BEQ     DrawDecompressSpace
    CLR     <TempByte
    LDA     #$AA
    BRA     StoreDecompressBar
DrawDecompressSpace:
    LDA     #$20
StoreDecompressBar:
    STA     ,U+
    DECB
    BNE     DrawDecompressBar

    JSR     DrawDecompressPercent
    RTS

DrawDecompressPercent:
    LDA     #$1D            * ]
    STA     ,U+
    LDA     <ProgressPercent
    CMPA    #100
    BNE     DrawPercentUnder100
    LDA     #$31            * 1
    STA     ,U+
    LDA     #$30            * 0
    STA     ,U+
    STA     ,U+
    LDA     #$25            * %
    STA     ,U+
    RTS

DrawPercentUnder100:
    LDB     #$20
    STB     ,U+
    LDB     #$20
    CMPA    #10
    BLO     StorePercentTens
    LDB     #$30
PercentTensLoop:
    CMPA    #10
    BLO     StorePercentTens
    SUBA    #10
    INCB
    BRA     PercentTensLoop
StorePercentTens:
    STB     ,U+
    ADDA    #$30
    STA     ,U+
    LDA     #$25            * %
    STA     ,U+
    RTS

ReadPacketHeader:
    JSR     ReadByte
    STA     <DestBlock
    STA     $FFA2

    JSR     ReadWord
    ADDD    #DEST_WINDOW
    STD     <DestPtr

    JSR     ReadWord
    STD     <OutRemaining

    JSR     ReadWord
    STD     <TempWord

    CLR     <BitMask
    LDA     #$FF
    STA     <LastCopyBlock
    RTS

DecodePacketBody:
    LDU     <DestPtr
NextCommand:
    LDD     <OutRemaining
    BEQ     PacketDone

    JSR     ReadBit
    TSTA
    BEQ     LiteralCommand

    JSR     ReadBit
    PSHS    A
    JSR     ReadElias
    STY     <RunLength
    PULS    A
    TSTA
    BEQ     RepeatCopyCommand

NewCopyCommand:
    JSR     ReadByte
    STA     <LastCopyBlock
    JSR     ReadWord
    STD     <LastCopyOffset
    BRA     CopyCommand

RepeatCopyCommand:
    LDA     <LastCopyBlock
    CMPA    #$FF
    BNE     CopyCommand
    JMP     StreamError

CopyCommand:
    JSR     SetupCopySource
    LDY     <RunLength
    LDD     <OutRemaining
    SUBD    <RunLength
    STD     <OutRemaining

CopyLoop:
    LDA     ,X+
    STA     ,U+
    LEAY    -1,Y
    BNE     CopyLoop
    BRA     NextCommand

LiteralCommand:
    JSR     ReadElias
    PSHS    Y
    LDD     <OutRemaining
    SUBD    ,S++
    STD     <OutRemaining
LiteralLoop:
    JSR     ReadByte
    STA     ,U+
    LEAY    -1,Y
    BNE     LiteralLoop
    BRA     NextCommand

PacketDone:
    STU     <DestPtr
    RTS

SetupCopySource:
    LDA     <LastCopyBlock
    CMPA    <DestBlock
    BEQ     CopyFromDestWindow

CopyFromMappedRam:
    STA     RAM_MODE_ENABLE
    STA     $FFA3
    LDD     <LastCopyOffset
    ADDD    #COPY_WINDOW
    TFR     D,X
    RTS

CopyFromDestWindow:
    LDD     <LastCopyOffset
    ADDD    #DEST_WINDOW
    TFR     D,X
    RTS

ReadByte:
    LDX     <InputPtr
    CMPX    <ChunkEnd
    BLO     ReadMappedSourceByte
    JMP     StreamError

ReadMappedSourceByte:
    LDA     ,X+
    STX     <InputPtr
    RTS

ReadWord:
    JSR     ReadByte
    TFR     A,B
    JSR     ReadByte
    PSHS    A
    TFR     B,A
    PULS    B
    RTS

ReadBit:
    LDA     <BitMask
    BNE     HaveBitControl

    JSR     ReadByte
    STA     <BitControl
    LDA     #$80
    STA     <BitMask

HaveBitControl:
    LDB     #0
    LDA     <BitControl
    BITA    <BitMask
    BEQ     ShiftBitMask
    LDB     #1

ShiftBitMask:
    LSR     <BitMask
    TFR     B,A
    RTS

ReadElias:
    LDY     #1
EliasLoop:
    JSR     ReadBit
    TSTA
    BNE     EliasDone

    TFR     Y,D
    LSLB
    ROLA
    TFR     D,Y

    JSR     ReadBit
    TSTA
    BEQ     EliasLoop
    LEAY    1,Y
    BRA     EliasLoop

EliasDone:
    RTS

RestoreAndLaunch:
* The loader kept BASIC/DOS alive in ROM mode while chunks were loaded.
* Switch back to all-RAM mode before restoring the user's final MMU map and
* jumping to the final handoff stub.
    CLRA
    STA     RAM_MODE_ENABLE

* Restore task 1 first.  This preserves programs that deliberately set
* $FFA8-$FFAF before EXEC.
    LDX     #UserMMUBlocks1
    LDU     #$FFA8
    LDB     #8
RestoreTask1:
    LDA     ,X+
    STA     ,U+
    DECB
    BNE     RestoreTask1

* This decoder is executing from bank 0, so bank 0 is restored by the final
* handoff stub.  The stub is generated below $E000 in one of final banks 1-6,
* so banks 1-7 can be restored before jumping to it.  A holds the final $FFA0
* physical block for the stub's first instruction.
    LDX     #UserMMUBlocks+1
    LDU     #$FFA1
    LDB     #7
RestoreTask0High:
    LDA     ,X+
    STA     ,U+
    DECB
    BNE     RestoreTask0High

    LDX     <FinalJumpAddr
    LDA     <UserMMUBlocks
    PSHS    A
    CLRA
    TFR     A,DP
    PULS    A
    JMP     ,X

DecompressText:
    FCB     $04,$05,$03,$0F,$0D,$10,$12,$05,$13,$13,$09,$0E,$07,$1B
