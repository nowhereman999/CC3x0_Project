' CC3_Comp.bas
'
' PC-side CoCo 3 compressed-loader builder.
'
' This is the first builder for the new extended ZX0-style loader.  It keeps
' the good parts of CC3_NewLoaderLZX0V1.4.bas:
'   - read one LOADM .BIN or a .lst of several LOADM files
'   - simulate CoCo 3 MMU writes while those LOADM records execute
'   - build a full 2 MB physical RAM image
'   - remember exactly which bytes were touched by the user's program
'
' It then replaces the old "fake LOADM records inside normal ZX0" compressor
' with a packet stream designed for the new 6809 decompressor:
'   - only touched/used bytes are compressed
'   - untouched gaps inside an MMU block are never written by the loader
'   - copy commands may point to any already-decompressed byte in 2 MB RAM
'   - command lengths use the same interlaced Elias style as zx0_Tool_07.BAS
'   - literal runs and copy runs are bit-coded like a small ZX0-like format
'
' Output files:
'   OUTNAME.CC3X0       binary packet stream for the future 6809 loader
'   OUTNAME_Report.txt  human-readable memory map and compression report
'   MOVER.BIN           first-stage Disk BASIC memory mover, patched for this program
'   CC3X0.BIN           second-stage streaming decompressor, built by the makefile
'   COMP0000.BIN...     8K-or-smaller packet-stream chunks for BASIC to LOADM
'
' This file intentionally does not shell out to zx0_Tool and does not depend
' on any helper Python program.  It is all QB64PE code.

$ScreenHide
$Console
_Dest _Console

Option Base 0

Const VERSION$ = "1.0"
Const BLOCK_SIZE = 8192
Const BLOCK_COUNT = 256
Const MEM_SIZE = BLOCK_SIZE * BLOCK_COUNT
Const HASH_SIZE = 65536
Const DEFAULT_MAX_CHAIN_CHECKS = 2048
Const LAZY_SCORE_MARGIN = 8
Const MIN_NEW_MATCH = 6
Const MIN_REPEAT_MATCH = 3
Const DEFAULT_MAX_PACKET_UNCOMP = 8192
Const ORDER_MAX_RANGES = 1024
Const ORDER_SAMPLE_STRIDE = 4
Const ORDER_CHAIN_CHECKS = 96
Const ORDER_MATCH_CAP = 96
Const ORDER_CURRENT_WEIGHT = 4
Const ORDER_FUTURE_WEIGHT = 1
Const METHOD2_TARGET_RANGE = 4096
Const METHOD2_MIN_SPLIT_RANGE = 6144
Const METHOD2_MIN_TAIL_RANGE = 1536
Const METHOD2_SPLIT_SEARCH = 1024
Const METHOD2_SPLIT_STEP = 32
Const METHOD2_BOUNDARY_SCAN = 64
Const METHOD3_PARSE_DEPTH = 3
Const METHOD3_CHAIN_CHECKS = 64
Const METHOD3_LOCAL_SCAN = 64
Const METHOD3_MAX_CANDIDATES = 12
Const METHOD4_MIN_FILL_RUN = 8
Const METHOD5_MIN_PATTERN_RUN = 8
Const METHOD5_MAX_PATTERN = 32
Const METHOD6_CHAIN_MULTIPLIER = 4
Const METHOD6_MAX_CHAIN_CHECKS = 32768
Const METHOD6_OLD_SAMPLE_STRIDE = 64
Const METHOD6_OLD_SAMPLE_LIMIT = 512
Const METHOD6_SEEN_CANDIDATES = 512
Const METHOD7_MIN_HASH_LENGTH = 4
Const METHOD7_MAX_HASH_LENGTH = 999
Const METHOD8_EXTRA_MIN_HASH_LENGTH = 5
Const DEFAULT_COMPRESSION_METHOD = 0
Const AUTO_NONE = 0
Const AUTO_BALANCED = 1
Const AUTO_FAST = 2
Const AUTO_BEST = 3
Const AUTO_ALL = 4
Const AUTO_TIE_BYTES = 16
Const CPU_ADDR_SPACE = 65536
Const CPU_IO_START = 65280
Const MMU0_START = 65440
Const MMU0_END = 65447
Const MMU1_START = 65448
Const MMU1_END = 65455
Const SOURCE_WINDOW_ADDR = 8192 ' $2000
Const TEXT_SCREEN_ADDR = 1024 ' $0400
Const TEXT_SCREEN_BYTES = 512
Const LOAD_PROGRESS_LINE_ADDR = 1504 ' $05E0, last 32-column text row
Const TEXT_LINE_BYTES = 32
Const LOAD_SCREEN_BYTES = TEXT_SCREEN_BYTES - TEXT_LINE_BYTES
Const LOAD_PROGRESS_HALF_STEPS = 38
Const MAX_LOAD_SCREEN_PERCENTS = 100
Const MAX_SOURCE_BLOCK_SCREENS = 128
Const STREAM_STATUS_ADDR = &H0F03
Const STREAM_CHUNK_LENGTH_ADDR = &H0F04
Const STREAM_CHUNK_FLAGS_ADDR = &H0F06
Const MOVER_SHADOW_COUNT_ADDR = &H1300
Const MOVER_LOAD_BLOCK_ADDR = &H1301
Const MOVER_DECODE_BLOCK_ADDR = &H1302
Const MOVER_SHADOW_PAIRS_ADDR = &H1303
Const STREAM_CHUNK_NEXT_DISK = 1
Const STREAM_CHUNK_FINAL = 2
Const STREAM_LOADM_OVERHEAD = 18
Const RSDOS_GRANULE_BYTES = 2304
Const RSDOS_DISK_GRANULES = 68
Const RSDOS_DIR_ENTRIES = 72

' BlockMap values.
Const BLOCK_UNUSED = 300
Const BLOCK_USER = 301
Const BLOCK_LOADER = 302
Const BLOCK_SHADOW = 303
Const BLOCK_SOURCE = 304

Type RangeType
    block As Long
    offset As Long
    length As Long
End Type

Type ShadowType
    originalBlock As Long
    shadowBlock As Long
End Type

ReDim Shared Memory(0 To MEM_SIZE - 1) As _Unsigned _Byte
ReDim Shared Used(0 To MEM_SIZE - 1) As _Unsigned _Byte
ReDim Shared Decoded(0 To MEM_SIZE - 1) As _Unsigned _Byte
ReDim Shared Hashed(0 To MEM_SIZE - 1) As _Unsigned _Byte
ReDim Shared HashHead(0 To HASH_SIZE - 1) As Long
ReDim Shared HashNext(0 To MEM_SIZE - 1) As Long
ReDim Shared Hashed4(0 To MEM_SIZE - 1) As _Unsigned _Byte
ReDim Shared Hash4Head(0 To HASH_SIZE - 1) As Long
ReDim Shared Hash4Next(0 To MEM_SIZE - 1) As Long
ReDim Shared HashedN(0 To MEM_SIZE - 1) As _Unsigned _Byte
ReDim Shared HashNHead(0 To HASH_SIZE - 1) As Long
ReDim Shared HashNNext(0 To MEM_SIZE - 1) As Long
ReDim Shared HashedM8(0 To 0) As _Unsigned _Byte
ReDim Shared HashM8Head(0 To 0) As Long
ReDim Shared HashM8Next(0 To 0) As Long
ReDim Shared Method8InputHash(0 To METHOD7_MAX_HASH_LENGTH) As Long
ReDim Shared BlockMap(0 To BLOCK_COUNT - 1) As Long
ReDim Shared ZeroFillBlock(0 To BLOCK_COUNT - 1) As _Unsigned _Byte
ReDim Shared PageBlock0(0 To 7) As Long
ReDim Shared PageBlock1(0 To 7) As Long
ReDim Shared SpecialBlock(0 To 4) As Long
ReDim Shared Ranges(0 To 1023) As RangeType
ReDim Shared Shadows(0 To 4) As ShadowType
ReDim Shared FileOut(0 To 65535) As _Unsigned _Byte
ReDim Shared CompOut(0 To 65535) As _Unsigned _Byte
ReDim Shared DiskOut(0 To 65535) As _Unsigned _Byte
ReDim Shared ShowLoadScreenPercent(0 To MAX_LOAD_SCREEN_PERCENTS - 1) As _Unsigned _Byte
ReDim Shared LoadScreenPercent(0 To MAX_LOAD_SCREEN_PERCENTS - 1, 0 To LOAD_SCREEN_BYTES - 1) As _Unsigned _Byte
ReDim Shared ShowLoadScreenBlock(0 To MAX_SOURCE_BLOCK_SCREENS - 1) As _Unsigned _Byte
ReDim Shared LoadScreenBlock(0 To MAX_SOURCE_BLOCK_SCREENS - 1, 0 To LOAD_SCREEN_BYTES - 1) As _Unsigned _Byte
ReDim Shared PacketStart(0 To 1023) As Long
ReDim Shared PacketLength(0 To 1023) As Long
ReDim Shared StreamChunkStart(0 To 1023) As Long
ReDim Shared StreamChunkBytes(0 To 1023) As Long
ReDim Shared StreamChunkFlags(0 To 1023) As Long
ReDim Shared StreamChunkDisk(0 To 1023) As Long
ReDim Shared RangeOrderPairScore(0 To 0) As Long
ReDim Shared RangeOrderForAbs(0 To 0) As Long
ReDim Shared AutoCandidateMethod(0 To 63) As Long
ReDim Shared AutoCandidateHash(0 To 63) As Long
ReDim Shared AutoResultName(0 To 63) As String
ReDim Shared AutoResultBytes(0 To 63) As Long
ReDim Shared AutoResultSeconds(0 To 63) As Double

Dim Shared RangeCount As Long
Dim Shared ShadowCount As Long
Dim Shared StreamHeaderLen As Long
Dim Shared StreamChunkCount As Long
Dim Shared FileOutLen As Long
Dim Shared CompOutLen As Long
Dim Shared DiskOutLen As Long
Dim Shared CompBitMask As Long
Dim Shared CompBitIndex As Long
Dim Shared ExecuteAddr As Long
Dim Shared FinalJumpAddr As Long
Dim Shared LoaderBlock As Long
Dim Shared SourceWindowBlock As Long
Dim Shared DecodeSourceBlock As Long
Dim Shared SourceWindowBorrowed As Long
Dim Shared MaxPacketUncomp As Long
Dim Shared MaxChainChecks As Long
Dim Shared LazyMatching As Long
Dim Shared CompressionMethod As Long
Dim Shared Method7HashLength As Long
Dim Shared ZeroFillEnabled As Long
Dim Shared ZeroFillValue As Long
Dim Shared ZeroFillBytes As Long
Dim Shared Verbose As Long
Dim Shared AutoMode As Long
Dim Shared AutoCandidateCount As Long
Dim Shared AutoResultCount As Long
Dim Shared AutoResultWinner As Long
Dim Shared PacketFileWriteEnabled As Long
Dim Shared AutoTrialActive As Long
Dim Shared LastCopySource As Long
Dim Shared PacketLiteralBytes As Long
Dim Shared PacketCopyBytes As Long
Dim Shared PacketLiteralCommands As Long
Dim Shared PacketCopyCommands As Long
Dim Shared TotalLiteralBytes As Long
Dim Shared TotalCopyBytes As Long
Dim Shared TotalLiteralCommands As Long
Dim Shared TotalCopyCommands As Long
Dim Shared TotalSourceFileBytes As Long
Dim Shared TotalUsedInputBytes As Long
Dim Shared RangeOrderMovedCount As Long
Dim Shared RangeOrderNormalCount As Long
Dim Shared RangeOrderSkipped As Long
Dim Shared Method2OriginalRangeCount As Long
Dim Shared Method2SplitRangeCount As Long
Dim Shared Method2ExtraRangeCount As Long
Dim Shared Method4FillBytes As Long
Dim Shared Method4FillCommands As Long
Dim Shared Method5PatternBytes As Long
Dim Shared Method5PatternCommands As Long
Dim Shared Method6Hash3Tests As Long
Dim Shared Method6Hash4Tests As Long
Dim Shared Method6OldSampleTests As Long
Dim Shared Method6DuplicateSkips As Long
Dim Shared Method7HashTests As Long
Dim Shared Method8HashTests As Long
Dim Shared ReadPos As Long
Dim Shared ReadBitMask As Long
Dim Shared ReadControlByte As Long

MaxPacketUncomp = DEFAULT_MAX_PACKET_UNCOMP
MaxChainChecks = DEFAULT_MAX_CHAIN_CHECKS
LazyMatching = 1
CompressionMethod = DEFAULT_COMPRESSION_METHOD
PacketFileWriteEnabled = 1
SpecialBlock(0) = &H38
SpecialBlock(1) = &H3C
SpecialBlock(2) = &H3D
SpecialBlock(3) = &H3E
SpecialBlock(4) = &H3F

Dim Fname As String
Dim FileList As String
Dim ScreenList As String
Dim ScreenCsv As String
Dim OutName As String
Dim Arg As String
Dim MethodText As String
Dim Method7Text As String
Dim Method8Text As String
Dim Method9Text As String
Dim AutoText As String
Dim i As Long
Dim ArgCount As Long
Dim ArgCapacity As Long
Dim ArgToken As String
Dim SplitPos As Long
Dim SplitOptionArg As Long
ReDim ParsedArg(0 To 31) As String

OutName = "CC3_COMP"

If _CommandCount = 0 Then GoTo Usage

ArgCapacity = 31
For i = 1 To _CommandCount
    Arg = Command$(i)
    SplitOptionArg = 0
    If InStr(LTrim$(Arg), "-") = 1 Then
        If InStr(Arg, " ") > 0 Then SplitOptionArg = 1
    End If
    If SplitOptionArg <> 0 Then
        Arg = LTrim$(RTrim$(Arg))
        Do While Arg <> ""
            SplitPos = InStr(Arg, " ")
            If SplitPos = 0 Then
                ArgToken = Arg
                Arg = ""
            Else
                ArgToken = Left$(Arg, SplitPos - 1)
                Arg = LTrim$(Mid$(Arg, SplitPos + 1))
            End If
            If ArgToken <> "" Then
                ArgCount = ArgCount + 1
                If ArgCount > ArgCapacity Then
                    ArgCapacity = ArgCapacity + 32
                    ReDim _Preserve ParsedArg(0 To ArgCapacity) As String
                End If
                ParsedArg(ArgCount) = ArgToken
            End If
        Loop
    Else
        ArgCount = ArgCount + 1
        If ArgCount > ArgCapacity Then
            ArgCapacity = ArgCapacity + 32
            ReDim _Preserve ParsedArg(0 To ArgCapacity) As String
        End If
        ParsedArg(ArgCount) = Arg
    End If
Next i

For i = 1 To ArgCount
    Arg = ParsedArg(i)
    If LCase$(Left$(Arg, 2)) = "-h" Or LCase$(Arg) = "--help" Or Arg = "-?" Then GoTo Usage
    If LCase$(Left$(Arg, 2)) = "-v" Then
        Verbose = Val(Mid$(Arg, 3))
        If Verbose = 0 Then Verbose = 1
        GoTo NextArg
    End If
    If LCase$(Arg) = "-q" Then
        LazyMatching = 0
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 2)) = "-d" Then
        Print "The -D option has been removed.  Use -A -Z00 for the stable auto mode."
        System
    End If
    If LCase$(Left$(Arg, 2)) = "-a" Then
        AutoText = LCase$(Mid$(Arg, 3))
        If Left$(AutoText, 1) = "=" Then AutoText = Mid$(AutoText, 2)
        If AutoText = "" Then
            AutoMode = AUTO_BALANCED
        ElseIf AutoText = "fast" Then
            AutoMode = AUTO_FAST
        ElseIf AutoText = "best" Then
            AutoMode = AUTO_BEST
        ElseIf AutoText = "all" Then
            AutoMode = AUTO_ALL
        Else
            Print "Invalid -A option.  Use -A, -Afast, -Abest, or -Aall."
            System
        End If
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 2)) = "-z" Then
        ZeroFillEnabled = 1
        ZeroFillValue = HexByteOption(Mid$(Arg, 3))
        If ZeroFillValue < 0 Then
            Print "Invalid -Z value.  Use -Z or -Zxx where xx is 00 to FF."
            System
        End If
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 2)) = "-m" And LCase$(Left$(Arg, 4)) <> "-max" Then
        MethodText = Mid$(Arg, 3)
        If Left$(MethodText, 1) = "=" Then MethodText = Mid$(MethodText, 2)
        If Left$(MethodText, 1) = "7" And Len(MethodText) > 1 Then
            Method7Text = Mid$(MethodText, 2)
            If Left$(Method7Text, 1) = "=" Then Method7Text = Mid$(Method7Text, 2)
            Method7HashLength = Val(Method7Text)
            If Method7HashLength < METHOD7_MIN_HASH_LENGTH Or Method7HashLength > METHOD7_MAX_HASH_LENGTH Then
                Print "Invalid -M7 hash length.  Use -M7### where ### is 4 to 999."
                System
            End If
            CompressionMethod = 7
        ElseIf Left$(MethodText, 1) = "8" And Len(MethodText) > 1 Then
            Method8Text = Mid$(MethodText, 2)
            If Left$(Method8Text, 1) = "=" Then Method8Text = Mid$(Method8Text, 2)
            Method7HashLength = Val(Method8Text)
            If Method7HashLength < METHOD7_MIN_HASH_LENGTH Or Method7HashLength > METHOD7_MAX_HASH_LENGTH Then
                Print "Invalid -M8 hash length.  Use -M8### where ### is 4 to 999."
                System
            End If
            CompressionMethod = 8
        ElseIf Left$(MethodText, 1) = "9" And Len(MethodText) > 1 Then
            Method9Text = Mid$(MethodText, 2)
            If Left$(Method9Text, 1) = "=" Then Method9Text = Mid$(Method9Text, 2)
            Method7HashLength = Val(Method9Text)
            If Method7HashLength < METHOD7_MIN_HASH_LENGTH Or Method7HashLength > METHOD7_MAX_HASH_LENGTH Then
                Print "Invalid -M9 hash length.  Use -M9### where ### is 4 to 999."
                System
            End If
            CompressionMethod = 9
        Else
            CompressionMethod = Val(MethodText)
            If CompressionMethod < 0 Or CompressionMethod > 6 Then
                Print "Invalid -M value.  Use -M0 through -M6, -M7###, -M8###, or -M9### with ### from 4 to 999."
                System
            End If
        End If
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 2)) = "-o" Then
        OutName = Mid$(Arg, 3)
        If UCase$(Right$(OutName, 4)) = ".BIN" Then OutName = Left$(OutName, Len(OutName) - 4)
        If UCase$(Right$(OutName, 6)) = ".CC3X0" Then OutName = Left$(OutName, Len(OutName) - 6)
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 4)) = "-max" Then
        MaxPacketUncomp = OptionNumber(Arg, 4)
        If MaxPacketUncomp < 256 Or MaxPacketUncomp > BLOCK_SIZE Then
            Print "Invalid -max value.  Use 256 to 8192 bytes."
            System
        End If
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 6)) = "-chain" Then
        MaxChainChecks = OptionNumber(Arg, 6)
        If MaxChainChecks < 1 Or MaxChainChecks > 4096 Then
            Print "Invalid -chain value.  Use 1 to 4096 checks."
            System
        End If
        GoTo NextArg
    End If
    If LCase$(Left$(Arg, 7)) = "-checks" Then
        MaxChainChecks = OptionNumber(Arg, 7)
        If MaxChainChecks < 1 Or MaxChainChecks > 4096 Then
            Print "Invalid -checks value.  Use 1 to 4096 checks."
            System
        End If
        GoTo NextArg
    End If
    If LCase$(Right$(Arg, 4)) = ".lst" Then
        FileList = Arg
        GoTo NextArg
    End If
    If LCase$(Right$(Arg, 5)) = ".scns" Then
        ScreenList = Arg
        GoTo NextArg
    End If
    If LCase$(Right$(Arg, 4)) = ".csv" Then
        ScreenCsv = Arg
        GoTo NextArg
    End If
    If LCase$(Right$(Arg, 4)) = ".bin" Then
        Fname = Arg
        GoTo NextArg
    End If
NextArg:
Next i

If Fname = "" And FileList = "" Then GoTo Usage

If Verbose > 0 Then
    Print "CC3_Comp v"; VERSION$; " - extended CoCo 3 compressor by Glen Hewlett"
    Print "Maximum uncompressed packet size:"; MaxPacketUncomp; "bytes"
    Print "Maximum hash-chain checks:"; MaxChainChecks
    If AutoMode <> AUTO_NONE Then
        Print "Auto compression mode: "; AutoModeName$
    Else
        Print "Compression method: "; MethodName$
    End If
    If ZeroFillEnabled <> 0 Then Print "Zero-fill internal gaps in used MMU blocks: value $"; Hex2$(ZeroFillValue)
    If LazyMatching <> 0 Then
        Print "One-byte lazy matching: on"
    Else
        Print "One-byte lazy matching: off"
    End If
End If

InitMemoryAndMMU
InitLoadScreens

If ScreenList <> "" And ScreenCsv <> "" Then
    Print "Use either one .scns file or one .csv file, not both."
    System
End If

If ScreenList <> "" Then
    LoadScreenList ScreenList
ElseIf ScreenCsv <> "" Then
    LoadScreenCsv ScreenCsv, 0
End If

If FileList <> "" Then
    LoadFileList FileList
Else
    ParseLoadMFile Fname
End If

InsertFinalHandoffStub
BuildBlockMap
If ZeroFillEnabled <> 0 Then MarkZeroFillBlocks
If Verbose > 0 Then Print "Used input bytes:"; TotalUsedInputBytes
ReserveLoaderAndShadowBlocks
If ZeroFillEnabled <> 0 Then FillUnusedBytesInMarkedBlocks
BuildUsedRanges
If AutoMode <> AUTO_NONE Then AutoSelectCompressionMethod
PrepareRangesForCompression
BuildCompressedPacketFile OutName
BuildStreamingLoadFiles OutName
BuildPatchedMoverFile
WriteReport OutName + "_Report.txt", OutName + ".CC3X0"

If Verbose > 0 Then
    Print
    Print "Wrote "; OutName; ".CC3X0"
    Print "Wrote MOVER.BIN"
    Print "Wrote CC3X0 streaming chunk files"
    Print "Wrote "; OutName; "_Report.txt"
    Print "Packets:"; RangeCount
    Print "Literal bytes:"; TotalLiteralBytes; " Copy bytes:"; TotalCopyBytes
End If
System

Usage:
Print "CC3_Comp v"; VERSION$
Print
Print "Usage:"
Print "  CC3_Comp FILENAME.BIN [-oOUTNAME] [-v] [-q] [-M#|-A...] [-Zxx] [-max####] [-chain####] [SCREEN.CSV|SCREENS.SCNS]"
Print "  CC3_Comp FILES.LST     [-oOUTNAME] [-v] [-q] [-M#|-A...] [-Zxx] [-max####] [-chain####] [SCREEN.CSV|SCREENS.SCNS]"
Print
Print "Where:"
Print "  FILENAME.BIN  is a CoCo LOADM file"
Print "  FILES.LST     lists several LOADM files, one per non-comment line"
Print "  SCREEN.CSV    optional 480-byte text-screen background shown while loading"
Print "  SCREENS.SCNS  optional list of load-percent,screen.csv entries"
Print
Print "Generated loader files:"
Print "  MOVER.BIN     LOADM/EXEC first; moves BASIC's low RAM and stack"
Print "  CC3X0.BIN     LOADM second; streaming decompressor at $0F00"
Print "  COMP####.BIN  LOADM one chunk at a time at $2000, then EXEC $0F00"
Print "  STREAMFILES.LST lists the generated COMP####.BIN files"
Print "  DISKFILES.LST  lists disk-number,COMP####.BIN assignments"
Print
Print "Runtime status byte:"
Print "  PEEK(&H0F03)=0 means load the next COMP####.BIN"
Print "  PEEK(&H0F03)=1 means ask for the next disk before continuing"
Print "  PEEK(&H0F03)=255 means the decompressor detected a stream error"
Print
Print "Options:"
Print "  -h, --help    show this help"
Print "  -oOUTNAME     write OUTNAME.CC3X0, OUTNAME_Report.txt, MOVER.BIN, and COMP####.BIN"
Print "  -v            verbose packet listing, or -v2 for extra LOADM parsing detail"
Print "  -q            quick mode: disables one-byte lazy matching"
Print "  -A            auto-select balanced compression method set, using -Zxx if supplied"
Print "  -Afast        auto-select from a quick candidate set"
Print "  -Abest        auto-select from a slower candidate set"
Print "  -Aall         auto-select from a very slow experimental candidate set"
Print "  -Zxx          fill internal unused gaps in used MMU blocks with hex byte xx, default -Z00"
Print "  -M0           compression method 0: original packet order, default"
Print "  -M1           compression method 1: range/block ordering before compression"
Print "  -M2           compression method 2: split large ranges, then range/block ordering"
Print "  -M3           compression method 3: range/block ordering plus bounded optimal/lazy parsing"
Print "  -M4           compression method 4: range/block ordering plus repeated-fill detection"
Print "  -M5           compression method 5: repeated-fill plus small repeating-pattern detection"
Print "  -M6           compression method 6: M5 plus wider 3/4-byte hash match search"
Print "  -M7###        compression method 7: M6 plus ###-byte hash, ### = 4 to 999"
Print "  -M8###        compression method 8: M7-style hashes from ### bytes down to 4"
Print "  -M9###        compression method 9: exhaustive hashes from 4 bytes up to ###"
Print "  -max####      max uncompressed bytes per packet, 256-8192, default 8192"
Print "  -chain####    max hash-chain matches tested per lookup, default 2048"
Print "  -checks####   alias for -chain####"
Print
Print "Examples:"
Print "  CC3_Comp NEW.BIN -oGO-V12"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M1"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M2"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M3"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M4"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M5"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M6"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M716"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M816"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M916"
Print "  CC3_Comp NEW.BIN -oGO-V12 -M716 -Z00"
Print "  CC3_Comp NEW.BIN -oGO-V12 -A"
Print "  CC3_Comp NEW.BIN -oGO-V12 -A -Z00"
Print "  CC3_Comp NEW.BIN -oGO-V12 -Afast"
Print "  CC3_Comp NEW.BIN -oGO-V12 -q"
Print "  CC3_Comp NEW.BIN -oGO-V12 -max4096 -chain128"
Print "  CC3_Comp NEW.BIN -oGO-V12 TITLE.CSV"
Print "  CC3_Comp NEW.BIN -oGO-V12 LOADSCREENS.SCNS"
Print
Print "SCREENS.SCNS example:"
Print "  0,title.csv"
Print "  50,halfway.csv"
Print "  85,almostdone.csv"
Print
System

Sub InitMemoryAndMMU
    Dim a As Long
    For a = 0 To MEM_SIZE - 1
        Used(a) = 0
        Decoded(a) = 0
    Next a
    For a = 0 To BLOCK_COUNT - 1
        BlockMap(a) = BLOCK_UNUSED
    Next a

    TotalSourceFileBytes = 0
    TotalUsedInputBytes = 0

    ' CoCo 3 BASIC default task-0 map.
    PageBlock0(0) = &H38
    PageBlock0(1) = &H39
    PageBlock0(2) = &H3A
    PageBlock0(3) = &H3B
    PageBlock0(4) = &H3C
    PageBlock0(5) = &H3D
    PageBlock0(6) = &H3E
    PageBlock0(7) = &H3F

    ' CoCo 3 BASIC default task-1 map used by the older loader code.
    PageBlock1(0) = &H38
    PageBlock1(1) = &H30
    PageBlock1(2) = &H31
    PageBlock1(3) = &H32
    PageBlock1(4) = &H33
    PageBlock1(5) = &H3D
    PageBlock1(6) = &H35
    PageBlock1(7) = &H3F
End Sub

Sub InitLoadScreens
    Dim percent As Long
    Dim blockIndex As Long
    Dim offset As Long

    For percent = 0 To MAX_LOAD_SCREEN_PERCENTS - 1
        ShowLoadScreenPercent(percent) = 0
        For offset = 0 To LOAD_SCREEN_BYTES - 1
            LoadScreenPercent(percent, offset) = &H20
        Next offset
    Next percent

    For blockIndex = 0 To MAX_SOURCE_BLOCK_SCREENS - 1
        ShowLoadScreenBlock(blockIndex) = 0
        For offset = 0 To LOAD_SCREEN_BYTES - 1
            LoadScreenBlock(blockIndex, offset) = &H20
        Next offset
    Next blockIndex
End Sub

Sub LoadScreenList (ListName As String)
    Dim lineText As String
    Dim commaPos As Long
    Dim loadPercent As Long
    Dim csvName As String

    If _FileExists(ListName) = 0 Then
        Print "Can't find loading-screen list: "; ListName
        System
    End If

    If Verbose > 0 Then Print "Reading loading-screen list "; ListName
    Open ListName For Input As #1
    Do Until EOF(1)
        Line Input #1, lineText
        lineText = LTrim$(RTrim$(lineText))
        If IsCommentOrBlank(lineText) = 0 Then
            commaPos = InStr(lineText, ",")
            If commaPos <= 1 Then
                Print "Bad .scns line, expected percent,csvfile: "; lineText
                System
            End If

            loadPercent = Val(Left$(lineText, commaPos - 1))
            If loadPercent < 0 Or loadPercent >= MAX_LOAD_SCREEN_PERCENTS Then
                Print "Bad .scns load percent"; loadPercent; ". Use 0 to 99."
                System
            End If

            csvName = LTrim$(RTrim$(Mid$(lineText, commaPos + 1)))
            LoadScreenCsv ResolveRelativeName$(ListName, csvName), loadPercent
        End If
    Loop
    Close #1
End Sub

Sub LoadScreenCsv (CsvName As String, loadPercent As Long)
    Dim f As Long
    Dim fileLen As Long
    Dim i As Long
    Dim c As Long
    Dim token As String
    Dim value As Long
    Dim outPos As Long

    If loadPercent < 0 Or loadPercent >= MAX_LOAD_SCREEN_PERCENTS Then
        Print "Internal error: loading-screen percent out of range."
        System
    End If

    If _FileExists(CsvName) = 0 Then
        Print "Can't find loading-screen CSV: "; CsvName
        System
    End If

    f = FreeFile
    Open CsvName For Binary As #f
    fileLen = LOF(f)
    If fileLen <= 0 Then
        Close #f
        Print "Loading-screen CSV is empty: "; CsvName
        System
    End If
    ReDim csvData(0 To fileLen - 1) As _Unsigned _Byte
    Get #f, , csvData()
    Close #f

    For i = 0 To LOAD_SCREEN_BYTES - 1
        LoadScreenPercent(loadPercent, i) = &H20
    Next i

    token = ""
    outPos = 0
    For i = 0 To fileLen - 1
        c = csvData(i)
        If c >= Asc("0") And c <= Asc("9") Then
            token = token + Chr$(c)
        Else
            If token <> "" Then
                value = Val(token)
                If value < 0 Or value > 255 Then
                    Print "CSV byte value out of range in "; CsvName; ": "; value
                    System
                End If
                If outPos < LOAD_SCREEN_BYTES Then
                    LoadScreenPercent(loadPercent, outPos) = value
                    outPos = outPos + 1
                End If
                token = ""
            End If
        End If
    Next i

    If token <> "" And outPos < LOAD_SCREEN_BYTES Then
        value = Val(token)
        If value < 0 Or value > 255 Then
            Print "CSV byte value out of range in "; CsvName; ": "; value
            System
        End If
        LoadScreenPercent(loadPercent, outPos) = value
        outPos = outPos + 1
    End If

    If outPos = 0 Then
        Print "No numeric screen bytes found in "; CsvName
        System
    End If

    ShowLoadScreenPercent(loadPercent) = 1
    If Verbose > 0 Then Print "Loaded screen CSV "; CsvName; " for load percent"; loadPercent; " bytes"; outPos
End Sub

Function ResolveRelativeName$ (BaseFile As String, ChildFile As String)
    Dim i As Long
    Dim slashPos As Long

    If ChildFile = "" Then
        ResolveRelativeName$ = ChildFile
        Exit Function
    End If

    If Left$(ChildFile, 1) = "/" Or Mid$(ChildFile, 2, 1) = ":" Then
        ResolveRelativeName$ = ChildFile
        Exit Function
    End If

    slashPos = 0
    For i = Len(BaseFile) To 1 Step -1
        If Mid$(BaseFile, i, 1) = "/" Or Mid$(BaseFile, i, 1) = "\" Then
            slashPos = i
            Exit For
        End If
    Next i

    If slashPos = 0 Then
        ResolveRelativeName$ = ChildFile
    Else
        ResolveRelativeName$ = Left$(BaseFile, slashPos) + ChildFile
    End If
End Function

Function IsCommentOrBlank (lineText As String)
    Dim firstChar As String
    lineText = LTrim$(RTrim$(lineText))
    If lineText = "" Then
        IsCommentOrBlank = 1
        Exit Function
    End If
    firstChar = Left$(lineText, 1)
    If firstChar = "*" Or firstChar = ";" Or firstChar = "#" Then
        IsCommentOrBlank = 1
    Else
        IsCommentOrBlank = 0
    End If
End Function

Sub LoadFileList (ListName As String)
    Dim LineText As String
    If _FileExists(ListName) = 0 Then
        Print "Can't find file list: "; ListName
        System
    End If
    If Verbose > 0 Then Print "Reading file list "; ListName
    Open ListName For Input As #1
    Do Until EOF(1)
        Line Input #1, LineText
        LineText = LTrim$(RTrim$(LineText))
        If Len(LineText) <> 0 Then
            If Left$(LineText, 1) <> "*" And Left$(LineText, 1) <> ";" And Left$(LineText, 1) <> "#" Then
                ParseLoadMFile LineText
            End If
        End If
    Loop
    Close #1
End Sub

Sub ParseLoadMFile (InputName As String)
    Dim f As Long
    Dim fileLen As Long
    Dim p As Long
    Dim marker As Long
    Dim blockLen As Long
    Dim memStart As Long
    Dim cpuAddr As Long
    Dim byteVal As Long
    Dim bank As Long
    Dim physBlock As Long
    Dim offset As Long
    Dim absAddr As Long
    Dim n As Long

    If _FileExists(InputName) = 0 Then
        Print "Can't find input file: "; InputName
        System
    End If

    f = FreeFile
    Open InputName For Binary As #f
    fileLen = LOF(f)
    If fileLen <= 0 Then
        Close #f
        Print "Input file is empty: "; InputName
        System
    End If
    TotalSourceFileBytes = TotalSourceFileBytes + fileLen
    ReDim InData(0 To fileLen - 1) As _Unsigned _Byte
    Get #f, , InData()
    Close #f

    If Verbose > 0 Then Print "Parsing "; InputName; " ("; fileLen; " bytes)"

    p = 0
    Do While p < fileLen
        marker = InData(p): p = p + 1
        If marker = &HFF Then
            If p + 3 >= fileLen Then
                Print "Corrupt LOADM EOF in "; InputName
                System
            End If
            blockLen = InData(p) * 256 + InData(p + 1): p = p + 2
            If blockLen <> 0 Then
                Print "Corrupt LOADM postamble length in "; InputName
                System
            End If
            ExecuteAddr = InData(p) * 256 + InData(p + 1)
            p = p + 2
            If Verbose > 0 Then Print "  EXEC $"; Hex4$(ExecuteAddr)
            Exit Sub
        End If

        If marker <> 0 Then
            Print "Corrupt LOADM marker $"; Hex2$(marker); " at file offset $"; Hex$(p - 1); " in "; InputName
            System
        End If

        If p + 3 >= fileLen Then
            Print "Corrupt LOADM data header in "; InputName
            System
        End If

        blockLen = InData(p) * 256 + InData(p + 1): p = p + 2
        memStart = InData(p) * 256 + InData(p + 1): p = p + 2

        If Verbose > 1 Then Print "  LOAD $"; Hex4$(memStart); " length $"; Hex4$(blockLen)

        For n = 0 To blockLen - 1
            If p >= fileLen Then
                Print "LOADM data block runs past end of file in "; InputName
                System
            End If
            cpuAddr = (memStart + n) Mod CPU_ADDR_SPACE
            byteVal = InData(p): p = p + 1

            If cpuAddr >= MMU0_START And cpuAddr <= MMU0_END Then
                PageBlock0(cpuAddr - MMU0_START) = byteVal
            ElseIf cpuAddr >= MMU1_START And cpuAddr <= MMU1_END Then
                PageBlock1(cpuAddr - MMU1_START) = byteVal
            ElseIf cpuAddr < CPU_IO_START Then
                bank = cpuAddr \ BLOCK_SIZE
                offset = cpuAddr And &H1FFF
                physBlock = PageBlock0(bank)
                absAddr = physBlock * BLOCK_SIZE + offset
                Memory(absAddr) = byteVal
                If Used(absAddr) = 0 Then TotalUsedInputBytes = TotalUsedInputBytes + 1
                Used(absAddr) = 1
            End If
        Next n
    Loop
End Sub

Sub BuildBlockMap
    Dim block As Long
    Dim offset As Long
    Dim absAddr As Long
    Dim blockUsed As Long

    For block = 0 To BLOCK_COUNT - 1
        blockUsed = 0
        For offset = 0 To BLOCK_SIZE - 1
            absAddr = block * BLOCK_SIZE + offset
            If Used(absAddr) <> 0 Then
                blockUsed = 1
                Exit For
            End If
        Next offset
        If blockUsed <> 0 Then BlockMap(block) = BLOCK_USER
    Next block
End Sub

Sub MarkZeroFillBlocks
    Dim block As Long
    ZeroFillBytes = 0
    For block = 0 To BLOCK_COUNT - 1
        ZeroFillBlock(block) = 0
        If BlockMap(block) = BLOCK_USER Then ZeroFillBlock(block) = 1
    Next block
End Sub

Sub FillUnusedBytesInMarkedBlocks
    Dim block As Long
    Dim offset As Long
    Dim absAddr As Long
    Dim firstUsed As Long
    Dim lastUsed As Long

    ZeroFillBytes = 0
    For block = 0 To BLOCK_COUNT - 1
        If ZeroFillBlock(block) <> 0 Then
            firstUsed = -1
            lastUsed = -1
            For offset = 0 To BLOCK_SIZE - 1
                absAddr = block * BLOCK_SIZE + offset
                If Used(absAddr) <> 0 Then
                    If firstUsed < 0 Then firstUsed = offset
                    lastUsed = offset
                End If
            Next offset

            If firstUsed >= 0 And lastUsed > firstUsed + 1 Then
                For offset = firstUsed + 1 To lastUsed - 1
                    absAddr = block * BLOCK_SIZE + offset
                    If Used(absAddr) = 0 Then
                        Memory(absAddr) = ZeroFillValue And &HFF
                        Used(absAddr) = 1
                        ZeroFillBytes = ZeroFillBytes + 1
                    End If
                Next offset
            End If
        End If
    Next block

    If Verbose > 0 Then Print "Zero-filled internal unused bytes in used MMU blocks:"; ZeroFillBytes; " value $"; Hex2$(ZeroFillValue)
End Sub

Sub InsertFinalHandoffStub
    Dim bank As Long
    Dim physBlock As Long
    Dim offset As Long
    Dim maxStart As Long
    Dim pass As Long
    Dim blockHasData As Long

    ' Pass 1: prefer gaps inside blocks the user's program already uses.
    ' Pass 2: fall back to a completely unused final-mapped block.
    '
    ' The streaming decompressor runs from logical bank 0 at $0F00.  It cannot
    ' restore $FFA0 while it is still executing there, so the final handoff stub
    ' must live in one of the final mapped banks 1-6.  Keep it below $E000:
    ' $FE00-$FFFF is vector/ROM-sensitive, and a stub at $FFFA is not reliably
    ' visible after the final MMU restore.
    For pass = 1 To 2
        For bank = 6 To 1 Step -1
            physBlock = PageBlock0(bank)
            blockHasData = BlockHasUsedBytes(physBlock)

            If (pass = 1 And blockHasData <> 0) Or (pass = 2 And blockHasData = 0) Then
                maxStart = &H1FFA

                For offset = maxStart To 0 Step -1
                    If PlaceFinalHandoffAt(bank, offset) <> 0 Then Exit Sub
                Next offset
            End If
        Next bank
    Next pass

    Print "Could not find six unused bytes below $E000 in final banks 1-6 for the final MMU handoff stub."
    System
End Sub

Function BlockHasUsedBytes (physBlock As Long)
    Dim offset As Long
    For offset = 0 To BLOCK_SIZE - 1
        If Used(physBlock * BLOCK_SIZE + offset) <> 0 Then
            BlockHasUsedBytes = 1
            Exit Function
        End If
    Next offset
    BlockHasUsedBytes = 0
End Function

Function PlaceFinalHandoffAt (bank As Long, offset As Long)
    Dim physBlock As Long
    Dim absAddr As Long
    Dim cpuAddr As Long
    Dim i As Long

    If bank < 1 Or bank > 6 Then
        PlaceFinalHandoffAt = 0
        Exit Function
    End If
    If offset < 0 Or offset > &H1FFA Then
        PlaceFinalHandoffAt = 0
        Exit Function
    End If

    physBlock = PageBlock0(bank)
    For i = 0 To 5
        If Used(physBlock * BLOCK_SIZE + offset + i) <> 0 Then
            PlaceFinalHandoffAt = 0
            Exit Function
        End If
    Next i

    absAddr = physBlock * BLOCK_SIZE + offset
    cpuAddr = bank * BLOCK_SIZE + offset
    Memory(absAddr + 0) = &HB7: Used(absAddr + 0) = 1 ' STA $FFA0
    Memory(absAddr + 1) = &HFF: Used(absAddr + 1) = 1
    Memory(absAddr + 2) = &HA0: Used(absAddr + 2) = 1
    Memory(absAddr + 3) = &H7E: Used(absAddr + 3) = 1 ' JMP ExecAddr
    Memory(absAddr + 4) = ExecuteAddr \ 256: Used(absAddr + 4) = 1
    Memory(absAddr + 5) = ExecuteAddr And &HFF: Used(absAddr + 5) = 1
    FinalJumpAddr = cpuAddr
    If Verbose > 0 Then Print "Final MMU handoff stub at CPU $"; Hex4$(FinalJumpAddr); " physical block $"; Hex2$(physBlock); " offset $"; Hex4$(offset)
    PlaceFinalHandoffAt = 1
End Function

Sub ReserveLoaderAndShadowBlocks
    Dim i As Long
    Dim needShadow38 As Long

    ' The streaming decoder lives in BASIC's logical bank 0 at $0F00.  BASIC is
    ' kept in its normal $38 low-RAM block for normal chunk loading.  Disk BASIC
    ' LOADM checks that the destination is writable, and physical blocks $3C-$3F
    ' fail that test while the machine is in ROM mode.  Keep BASIC's LOADM
    ' target on a ROM-mode-writable block, then optionally copy the loaded 8K
    ' chunk to a separate decode-source block after the decoder switches to RAM
    ' mode.  That lets $3C-$3F still be used as loader scratch on tight 128K
    ' layouts without making Disk BASIC load directly into those blocks.
    ShadowCount = 0

    needShadow38 = 0
    If BlockMap(&H38) = BLOCK_USER Then needShadow38 = 1

    SourceWindowBorrowed = 0
    SourceWindowBlock = FindUnusedRomModeLoadBlock
    If SourceWindowBlock < 0 Then
        DecodeSourceBlock = FindUnusedDecodeSourceBlock(-1, -1)
        If DecodeSourceBlock < 0 Then
            Print "No free block available for the decoder source copy."
            System
        End If

        SourceWindowBlock = FindBorrowedRomModeLoadBlock(DecodeSourceBlock)
        If SourceWindowBlock < 0 Then
            Print "No ROM-mode-writable block can be borrowed for Disk BASIC LOADM."
            System
        End If
        SourceWindowBorrowed = 1
    Else
        DecodeSourceBlock = SourceWindowBlock
    End If

    BlockMap(SourceWindowBlock) = BLOCK_SOURCE
    If DecodeSourceBlock <> SourceWindowBlock Then BlockMap(DecodeSourceBlock) = BLOCK_SOURCE

    If needShadow38 <> 0 Then AddShadowForBlock &H38

    ' This header byte is informational in the streaming loader.  Reuse it to
    ' record the current Disk BASIC LOADM source-window block for diagnostics.
    LoaderBlock = SourceWindowBlock

    If Verbose > 0 Then
        Print "Disk BASIC LOADM source block: $"; Hex2$(SourceWindowBlock)
        If SourceWindowBorrowed <> 0 Then Print "  borrowed from user data and delayed until final decode"
        Print "Decoder source block: $"; Hex2$(DecodeSourceBlock)
        If ShadowCount > 0 Then
            Print "Disk BASIC shadow blocks:"
            For i = 0 To ShadowCount - 1
                Print "  $"; Hex2$(Shadows(i).originalBlock); " -> $"; Hex2$(Shadows(i).shadowBlock)
            Next i
        Else
            Print "No protected Disk BASIC blocks need shadowing."
        End If
    End If
End Sub

Sub AddShadowForBlock (originalBlock As Long)
    Dim shadow As Long

    If ShadowCount > UBound(Shadows) Then
        Print "Internal error: too many shadow blocks requested."
        System
    End If

    shadow = FindShadowBlock(originalBlock)
    If shadow < 0 Then
        Print "No free block available to shadow protected block $"; Hex2$(originalBlock)
        System
    End If

    BlockMap(shadow) = BLOCK_SHADOW
    Shadows(ShadowCount).originalBlock = originalBlock
    Shadows(ShadowCount).shadowBlock = shadow
    ShadowCount = ShadowCount + 1
End Sub

Function FindFreeBlock
    Dim b As Long
    For b = &H3F To 0 Step -1
        If BlockMap(b) = BLOCK_UNUSED Then
            FindFreeBlock = b
            Exit Function
        End If
    Next b

    For b = &H40 To BLOCK_COUNT - 1
        If BlockMap(b) = BLOCK_UNUSED Then
            FindFreeBlock = b
            Exit Function
        End If
    Next b

    FindFreeBlock = -1
End Function

Function FindFreeBlockExcept (avoidBlock As Long)
    Dim b As Long
    For b = &H3F To 0 Step -1
        If b <> avoidBlock And BlockMap(b) = BLOCK_UNUSED Then
            FindFreeBlockExcept = b
            Exit Function
        End If
    Next b

    For b = &H40 To BLOCK_COUNT - 1
        If b <> avoidBlock And BlockMap(b) = BLOCK_UNUSED Then
            FindFreeBlockExcept = b
            Exit Function
        End If
    Next b

    FindFreeBlockExcept = -1
End Function

Function FindUnusedRomModeLoadBlock
    Dim b As Long

    For b = &H3F To 0 Step -1
        If IsRomModeLoadWritableBlock(b) <> 0 And BlockMap(b) = BLOCK_UNUSED Then
            FindUnusedRomModeLoadBlock = b
            Exit Function
        End If
    Next b

    For b = &H40 To BLOCK_COUNT - 1
        If BlockMap(b) = BLOCK_UNUSED Then
            FindUnusedRomModeLoadBlock = b
            Exit Function
        End If
    Next b

    FindUnusedRomModeLoadBlock = -1
End Function

Function FindBorrowedRomModeLoadBlock (avoidBlock As Long)
    Dim b As Long
    Dim bestBlock As Long
    Dim bestUsed As Long
    Dim usedBytes As Long

    bestBlock = -1
    bestUsed = BLOCK_SIZE + 1
    For b = &H3F To 0 Step -1
        If b <> avoidBlock And IsRomModeLoadWritableBlock(b) <> 0 And BlockMap(b) = BLOCK_USER Then
            usedBytes = UsedBytesInBlock(b)
            If usedBytes < bestUsed Then
                bestUsed = usedBytes
                bestBlock = b
            End If
        End If
    Next b

    For b = &H40 To BLOCK_COUNT - 1
        If b <> avoidBlock And BlockMap(b) = BLOCK_USER Then
            usedBytes = UsedBytesInBlock(b)
            If usedBytes < bestUsed Then
                bestUsed = usedBytes
                bestBlock = b
            End If
        End If
    Next b

    FindBorrowedRomModeLoadBlock = bestBlock
End Function

Function UsedBytesInBlock (blockNum As Long)
    Dim offset As Long
    Dim total As Long

    total = 0
    For offset = 0 To BLOCK_SIZE - 1
        If Used(blockNum * BLOCK_SIZE + offset) <> 0 Then total = total + 1
    Next offset
    UsedBytesInBlock = total
End Function

Function FindUnusedDecodeSourceBlock (avoidBlock1 As Long, avoidBlock2 As Long)
    Dim b As Long

    For b = &H3F To 0 Step -1
        If b <> avoidBlock1 And b <> avoidBlock2 And b <> &H38 And BlockMap(b) = BLOCK_UNUSED Then
            FindUnusedDecodeSourceBlock = b
            Exit Function
        End If
    Next b

    For b = &H40 To BLOCK_COUNT - 1
        If b <> avoidBlock1 And b <> avoidBlock2 And BlockMap(b) = BLOCK_UNUSED Then
            FindUnusedDecodeSourceBlock = b
            Exit Function
        End If
    Next b

    FindUnusedDecodeSourceBlock = -1
End Function

Function FindShadowBlock (originalBlock As Long)
    Dim b As Long

    For b = &H3F To 0 Step -1
        If b <> originalBlock And b <> &H38 And BlockMap(b) = BLOCK_UNUSED Then
            FindShadowBlock = b
            Exit Function
        End If
    Next b

    For b = &H40 To BLOCK_COUNT - 1
        If b <> originalBlock And BlockMap(b) = BLOCK_UNUSED Then
            FindShadowBlock = b
            Exit Function
        End If
    Next b

    FindShadowBlock = -1
End Function

Function IsRomModeLoadWritableBlock (blockNum As Long)
    If blockNum = &H38 Then
        IsRomModeLoadWritableBlock = 0
    ElseIf blockNum >= &H3C And blockNum <= &H3F Then
        IsRomModeLoadWritableBlock = 0
    Else
        IsRomModeLoadWritableBlock = 1
    End If
End Function

Sub BuildUsedRanges
    Dim block As Long
    Dim offset As Long
    Dim startOffset As Long
    Dim runLen As Long
    Dim remaining As Long
    Dim chunkLen As Long

    RangeCount = 0
    For block = 0 To BLOCK_COUNT - 1
        offset = 0
        Do While offset < BLOCK_SIZE
            If Used(block * BLOCK_SIZE + offset) <> 0 Then
                startOffset = offset
                runLen = 0
                Do While offset < BLOCK_SIZE
                    If Used(block * BLOCK_SIZE + offset) = 0 Then Exit Do
                    runLen = runLen + 1
                    offset = offset + 1
                Loop

                remaining = runLen
                Do While remaining > 0
                    chunkLen = remaining
                    If chunkLen > MaxPacketUncomp Then chunkLen = MaxPacketUncomp
                    AddRange block, startOffset + (runLen - remaining), chunkLen
                    remaining = remaining - chunkLen
                Loop
            Else
                offset = offset + 1
            End If
        Loop
    Next block
End Sub

Sub SplitRangesForMethod2
    Dim oldCount As Long
    Dim newCount As Long
    Dim i As Long
    Dim remaining As Long
    Dim nextOffset As Long
    Dim splitLen As Long
    Dim maxNewRanges As Long

    Method2OriginalRangeCount = RangeCount
    Method2SplitRangeCount = RangeCount
    Method2ExtraRangeCount = 0

    If RangeCount <= 0 Then Exit Sub

    oldCount = RangeCount
    maxNewRanges = oldCount * ((BLOCK_SIZE \ METHOD2_TARGET_RANGE) + 2)
    If maxNewRanges < oldCount + 16 Then maxNewRanges = oldCount + 16
    ReDim splitRanges(0 To maxNewRanges - 1) As RangeType

    For i = 0 To oldCount - 1
        If IsFinalProtectedBlock(Ranges(i).block) <> 0 Or Ranges(i).length < METHOD2_MIN_SPLIT_RANGE Then
            Method2AddSplitRange splitRanges(), newCount, Ranges(i).block, Ranges(i).offset, Ranges(i).length
        Else
            remaining = Ranges(i).length
            nextOffset = Ranges(i).offset
            Do While remaining > 0
                If remaining <= METHOD2_TARGET_RANGE + METHOD2_MIN_TAIL_RANGE Then
                    splitLen = remaining
                Else
                    splitLen = Method2ChooseSplitLength(Ranges(i).block, nextOffset, remaining)
                End If

                Method2AddSplitRange splitRanges(), newCount, Ranges(i).block, nextOffset, splitLen
                nextOffset = nextOffset + splitLen
                remaining = remaining - splitLen
            Loop
        End If
    Next i

    If newCount > UBound(Ranges) + 1 Then ReDim _Preserve Ranges(0 To newCount + 1023) As RangeType
    For i = 0 To newCount - 1
        Ranges(i) = splitRanges(i)
    Next i
    RangeCount = newCount

    Method2SplitRangeCount = newCount
    Method2ExtraRangeCount = newCount - oldCount

    If Verbose > 0 Then Print "Method -M2 split packet ranges from"; oldCount; "to"; newCount; "before ordering."
End Sub

Sub Method2AddSplitRange (splitRanges() As RangeType, newCount As Long, block As Long, offset As Long, length As Long)
    If newCount > UBound(splitRanges) Then
        ReDim _Preserve splitRanges(0 To UBound(splitRanges) + 1024) As RangeType
    End If
    splitRanges(newCount).block = block
    splitRanges(newCount).offset = offset
    splitRanges(newCount).length = length
    newCount = newCount + 1
End Sub

Function Method2ChooseSplitLength (block As Long, offset As Long, remaining As Long)
    Dim minLen As Long
    Dim maxLen As Long
    Dim candidate As Long
    Dim bestLen As Long
    Dim bestScore As Long
    Dim score As Long
    Dim targetDistance As Long
    Dim fallbackLen As Long

    minLen = METHOD2_TARGET_RANGE - METHOD2_SPLIT_SEARCH
    maxLen = METHOD2_TARGET_RANGE + METHOD2_SPLIT_SEARCH

    If minLen < METHOD2_MIN_TAIL_RANGE Then minLen = METHOD2_MIN_TAIL_RANGE
    If maxLen > remaining - METHOD2_MIN_TAIL_RANGE Then maxLen = remaining - METHOD2_MIN_TAIL_RANGE

    If maxLen < minLen Then
        fallbackLen = METHOD2_TARGET_RANGE
        If fallbackLen > remaining Then fallbackLen = remaining
        Method2ChooseSplitLength = fallbackLen
        Exit Function
    End If

    candidate = ((minLen + METHOD2_SPLIT_STEP - 1) \ METHOD2_SPLIT_STEP) * METHOD2_SPLIT_STEP
    bestLen = candidate
    bestScore = 2147483647

    Do While candidate <= maxLen
        targetDistance = candidate - METHOD2_TARGET_RANGE
        If targetDistance < 0 Then targetDistance = -targetDistance
        score = Method2BoundaryScore(block, offset + candidate) * 16 + targetDistance \ METHOD2_SPLIT_STEP
        If score < bestScore Then
            bestScore = score
            bestLen = candidate
        End If
        candidate = candidate + METHOD2_SPLIT_STEP
    Loop

    Method2ChooseSplitLength = bestLen
End Function

Function Method2BoundaryScore (block As Long, splitOffset As Long)
    Dim absAddr As Long
    Dim scan As Long
    Dim i As Long
    Dim leftAbs As Long
    Dim rightAbs As Long
    Dim score As Long

    absAddr = block * BLOCK_SIZE + splitOffset
    scan = METHOD2_BOUNDARY_SCAN
    If scan > splitOffset Then scan = splitOffset
    If scan > BLOCK_SIZE - splitOffset Then scan = BLOCK_SIZE - splitOffset

    score = 0
    For i = 1 To scan
        leftAbs = absAddr - i
        rightAbs = absAddr + i - 1
        If Used(leftAbs) <> 0 And Used(rightAbs) <> 0 Then
            If Memory(leftAbs) = Memory(rightAbs) Then score = score + 2
        End If
    Next i

    For i = 1 To scan - 2 Step 4
        leftAbs = absAddr - i - 2
        rightAbs = absAddr + i - 1
        If leftAbs >= block * BLOCK_SIZE And rightAbs + 2 < (block + 1) * BLOCK_SIZE Then
            If Used(leftAbs) <> 0 And Used(leftAbs + 1) <> 0 And Used(leftAbs + 2) <> 0 Then
                If Used(rightAbs) <> 0 And Used(rightAbs + 1) <> 0 And Used(rightAbs + 2) <> 0 Then
                    If HashAt(leftAbs) = HashAt(rightAbs) Then score = score + 3
                End If
            End If
        End If
    Next i

    Method2BoundaryScore = score
End Function

Sub OrderRangesForCompression
    Dim i As Long
    Dim normalCount As Long
    Dim finalCount As Long
    Dim outIndex As Long

    RangeOrderMovedCount = 0
    RangeOrderNormalCount = 0
    RangeOrderSkipped = 0

    If RangeCount <= 2 Then Exit Sub

    If RangeCount > ORDER_MAX_RANGES Then
        RangeOrderSkipped = 1
        If Verbose > 0 Then Print "Range ordering skipped: "; RangeCount; " packet ranges exceeds limit "; ORDER_MAX_RANGES
        Exit Sub
    End If

    ReDim normalIndex(0 To RangeCount - 1) As Long
    ReDim finalIndex(0 To RangeCount - 1) As Long
    ReDim orderedNormal(0 To RangeCount - 1) As Long
    ReDim orderedRanges(0 To RangeCount - 1) As RangeType

    For i = 0 To RangeCount - 1
        If IsFinalProtectedBlock(Ranges(i).block) <> 0 Then
            finalIndex(finalCount) = i
            finalCount = finalCount + 1
        Else
            normalIndex(normalCount) = i
            normalCount = normalCount + 1
        End If
    Next i

    RangeOrderNormalCount = normalCount
    If normalCount <= 2 Then Exit Sub

    BuildRangeOrderPairScores normalIndex(), normalCount
    OrderNormalRangeIndexes normalIndex(), normalCount, orderedNormal()

    outIndex = 0
    For i = 0 To normalCount - 1
        orderedRanges(outIndex) = Ranges(orderedNormal(i))
        If orderedNormal(i) <> normalIndex(i) Then RangeOrderMovedCount = RangeOrderMovedCount + 1
        outIndex = outIndex + 1
    Next i
    For i = 0 To finalCount - 1
        orderedRanges(outIndex) = Ranges(finalIndex(i))
        outIndex = outIndex + 1
    Next i

    For i = 0 To RangeCount - 1
        Ranges(i) = orderedRanges(i)
    Next i

    Erase RangeOrderPairScore
    Erase RangeOrderForAbs

    If Verbose > 0 Then Print "Range ordering considered"; normalCount; "normal packet ranges and moved"; RangeOrderMovedCount; "of them."
End Sub

Sub BuildRangeOrderPairScores (normalIndex() As Long, normalCount As Long)
    Dim h As Long
    Dim i As Long
    Dim slot As Long
    Dim r As Long
    Dim sourceAbs As Long
    Dim startAbs As Long
    Dim endAbs As Long
    Dim candidate As Long
    Dim checks As Long
    Dim targetRange As Long
    Dim matchLen As Long

    ReDim RangeOrderPairScore(0 To RangeCount * RangeCount - 1) As Long
    ReDim RangeOrderForAbs(0 To MEM_SIZE - 1) As Long

    For h = 0 To HASH_SIZE - 1
        HashHead(h) = -1
    Next h
    For i = 0 To MEM_SIZE - 1
        HashNext(i) = -1
        RangeOrderForAbs(i) = -1
    Next i

    For slot = 0 To normalCount - 1
        r = normalIndex(slot)
        startAbs = Ranges(r).block * BLOCK_SIZE + Ranges(r).offset
        endAbs = startAbs + Ranges(r).length - 1
        For sourceAbs = startAbs To endAbs
            RangeOrderForAbs(sourceAbs) = r
        Next sourceAbs
    Next slot

    For slot = 0 To normalCount - 1
        r = normalIndex(slot)
        startAbs = Ranges(r).block * BLOCK_SIZE + Ranges(r).offset
        endAbs = startAbs + Ranges(r).length - 1
        For sourceAbs = startAbs To endAbs - 2
            If CanInputHashAt(sourceAbs) <> 0 Then
                h = HashAt(sourceAbs)
                HashNext(sourceAbs) = HashHead(h)
                HashHead(h) = sourceAbs
            End If
        Next sourceAbs
    Next slot

    For slot = 0 To normalCount - 1
        r = normalIndex(slot)
        startAbs = Ranges(r).block * BLOCK_SIZE + Ranges(r).offset
        endAbs = startAbs + Ranges(r).length - 1
        For sourceAbs = startAbs To endAbs - 2 Step ORDER_SAMPLE_STRIDE
            If CanInputHashAt(sourceAbs) <> 0 Then
                h = HashAt(sourceAbs)
                candidate = HashHead(h)
                checks = 0
                Do While candidate >= 0 And checks < ORDER_CHAIN_CHECKS
                    targetRange = RangeOrderForAbs(candidate)
                    If targetRange >= 0 And targetRange <> r Then
                        matchLen = RangeOrderMatchLength(sourceAbs, candidate, r, targetRange)
                        If matchLen >= MIN_NEW_MATCH Then AddRangeOrderPairScore r, targetRange, matchLen
                    End If
                    candidate = HashNext(candidate)
                    checks = checks + 1
                Loop
            End If
        Next sourceAbs
    Next slot
End Sub

Sub OrderNormalRangeIndexes (normalIndex() As Long, normalCount As Long, orderedNormal() As Long)
    Dim orderPos As Long
    Dim slot As Long
    Dim other As Long
    Dim candidate As Long
    Dim bestSlot As Long
    Dim bestFuture As _Integer64
    Dim bestScore As _Integer64
    Dim currentScore As _Integer64
    Dim futureScore As _Integer64
    Dim score As _Integer64

    ReDim chosen(0 To normalCount - 1) As _Unsigned _Byte

    For orderPos = 0 To normalCount - 1
        bestSlot = -1
        bestScore = -1
        bestFuture = -1

        For slot = 0 To normalCount - 1
            If chosen(slot) = 0 Then
                candidate = normalIndex(slot)
                currentScore = 0
                futureScore = 0

                For other = 0 To normalCount - 1
                    If chosen(other) <> 0 Then
                        currentScore = currentScore + RangeOrderPair(normalIndex(other), candidate)
                    ElseIf other <> slot Then
                        futureScore = futureScore + RangeOrderPair(candidate, normalIndex(other))
                    End If
                Next other

                score = currentScore * ORDER_CURRENT_WEIGHT + futureScore * ORDER_FUTURE_WEIGHT
                If score > bestScore Or (score = bestScore And futureScore > bestFuture) Then
                    bestScore = score
                    bestFuture = futureScore
                    bestSlot = slot
                End If
            End If
        Next slot

        If bestSlot < 0 Then bestSlot = orderPos
        orderedNormal(orderPos) = normalIndex(bestSlot)
        chosen(bestSlot) = 1
    Next orderPos
End Sub

Function RangeOrderPair (sourceRange As Long, targetRange As Long)
    RangeOrderPair = RangeOrderPairScore(sourceRange * RangeCount + targetRange)
End Function

Sub AddRangeOrderPairScore (sourceRange As Long, targetRange As Long, value As Long)
    Dim scoreIndex As Long
    scoreIndex = sourceRange * RangeCount + targetRange
    If RangeOrderPairScore(scoreIndex) > 2000000000 - value Then
        RangeOrderPairScore(scoreIndex) = 2000000000
    Else
        RangeOrderPairScore(scoreIndex) = RangeOrderPairScore(scoreIndex) + value
    End If
End Sub

Function RangeOrderMatchLength (sourceAbs As Long, targetAbs As Long, sourceRange As Long, targetRange As Long)
    Dim maxLen As Long
    Dim sourceEnd As Long
    Dim targetEnd As Long
    Dim sourceBlockRemaining As Long
    Dim l As Long

    sourceEnd = Ranges(sourceRange).block * BLOCK_SIZE + Ranges(sourceRange).offset + Ranges(sourceRange).length
    targetEnd = Ranges(targetRange).block * BLOCK_SIZE + Ranges(targetRange).offset + Ranges(targetRange).length
    sourceBlockRemaining = BLOCK_SIZE - (sourceAbs And &H1FFF)

    maxLen = ORDER_MATCH_CAP
    If maxLen > sourceEnd - sourceAbs Then maxLen = sourceEnd - sourceAbs
    If maxLen > targetEnd - targetAbs Then maxLen = targetEnd - targetAbs
    If maxLen > sourceBlockRemaining Then maxLen = sourceBlockRemaining

    l = 0
    Do While l < maxLen
        If Used(sourceAbs + l) = 0 Or Used(targetAbs + l) = 0 Then Exit Do
        If Memory(sourceAbs + l) <> Memory(targetAbs + l) Then Exit Do
        l = l + 1
    Loop

    RangeOrderMatchLength = l
End Function

Sub MoveProtectedRangesToEnd
    Dim i As Long
    Dim normalCount As Long
    Dim finalCount As Long
    Dim outIndex As Long

    If RangeCount <= 1 Then Exit Sub

    ReDim normalRanges(0 To RangeCount - 1) As RangeType
    ReDim finalRanges(0 To RangeCount - 1) As RangeType

    ' Physical block $38 contains Disk BASIC's low RAM and the resident loader.
    ' A borrowed LOADM source block is overwritten by every COMP####.BIN load.
    ' Keep both kinds of packets at the end so BASIC never has to run after
    ' their final user contents have been restored.
    For i = 0 To RangeCount - 1
        If IsFinalProtectedBlock(Ranges(i).block) <> 0 Then
            finalRanges(finalCount) = Ranges(i)
            finalCount = finalCount + 1
        Else
            normalRanges(normalCount) = Ranges(i)
            normalCount = normalCount + 1
        End If
    Next i

    If finalCount = 0 Then Exit Sub

    outIndex = 0
    For i = 0 To normalCount - 1
        Ranges(outIndex) = normalRanges(i)
        outIndex = outIndex + 1
    Next i
    For i = 0 To finalCount - 1
        Ranges(outIndex) = finalRanges(i)
        outIndex = outIndex + 1
    Next i

    If Verbose > 0 Then Print "Moved"; finalCount; "protected BASIC low-RAM packet range(s) to the final decode chunk."
End Sub

Function IsFinalProtectedBlock (block As Long)
    If block = &H38 Then
        IsFinalProtectedBlock = 1
    ElseIf SourceWindowBorrowed <> 0 And block = SourceWindowBlock Then
        IsFinalProtectedBlock = 1
    Else
        IsFinalProtectedBlock = 0
    End If
End Function

Sub AddRange (block As Long, offset As Long, length As Long)
    If RangeCount > UBound(Ranges) Then
        ReDim _Preserve Ranges(0 To UBound(Ranges) + 1024) As RangeType
    End If
    Ranges(RangeCount).block = block
    Ranges(RangeCount).offset = offset
    Ranges(RangeCount).length = length
    RangeCount = RangeCount + 1
End Sub

Sub PrepareRangesForCompression
    ResetRangeTransformStats
    If CompressionMethod = 2 Then SplitRangesForMethod2
    If CompressionMethod >= 1 Then OrderRangesForCompression
    MoveProtectedRangesToEnd
End Sub

Sub ResetRangeTransformStats
    RangeOrderMovedCount = 0
    RangeOrderNormalCount = 0
    RangeOrderSkipped = 0
    Method2OriginalRangeCount = 0
    Method2SplitRangeCount = 0
    Method2ExtraRangeCount = 0
End Sub

Sub AutoSelectCompressionMethod
    Dim baseCount As Long
    Dim i As Long
    Dim trial As Long
    Dim savedVerbose As Long
    Dim savedMethod As Long
    Dim savedHashLength As Long
    Dim bestIndex As Long
    Dim bestBytes As Long
    Dim bestSeconds As Double
    Dim trialStart As Double
    Dim trialSeconds As Double
    Dim trialBytes As Long

    baseCount = RangeCount
    If baseCount <= 0 Then Exit Sub

    ReDim baseRanges(0 To baseCount - 1) As RangeType
    For i = 0 To baseCount - 1
        baseRanges(i) = Ranges(i)
    Next i

    savedVerbose = Verbose
    savedMethod = CompressionMethod
    savedHashLength = Method7HashLength
    AutoResultCount = 0
    AutoResultWinner = -1
    BuildAutoCandidateSet AutoMode

    If savedVerbose > 0 Then
        Print "Auto compression mode: "; AutoModeName$
        If ZeroFillEnabled <> 0 Then
            Print "Auto mode uses -Z$"; Hex2$(ZeroFillValue); " for every candidate."
        Else
            Print "Auto mode tests methods with zero-fill off."
        End If
    End If

    PacketFileWriteEnabled = 0
    AutoTrialActive = 1
    Verbose = 0

    bestIndex = -1
    bestBytes = 2147483647
    bestSeconds = 0

    For trial = 0 To AutoCandidateCount - 1
        RestoreBaseRanges baseRanges(), baseCount
        CompressionMethod = AutoCandidateMethod(trial)
        Method7HashLength = AutoCandidateHash(trial)

        trialStart = Timer
        PrepareRangesForCompression
        BuildCompressedPacketFile "__AUTO_TEST__"
        trialSeconds = Timer - trialStart
        If trialSeconds < 0 Then trialSeconds = trialSeconds + 86400
        trialBytes = FileOutLen

        EnsureAutoResultCapacity AutoResultCount
        AutoResultName(AutoResultCount) = MethodName$
        AutoResultBytes(AutoResultCount) = trialBytes
        AutoResultSeconds(AutoResultCount) = trialSeconds

        If savedVerbose > 0 Then
            Print "  "; AutoResultName(AutoResultCount); " "; trialBytes; " bytes "; FormatSeconds$(trialSeconds); "s"
        End If

        If AutoCandidateBeatsBest(trialBytes, trialSeconds, bestBytes, bestSeconds, bestIndex) <> 0 Then
            bestIndex = AutoResultCount
            bestBytes = trialBytes
            bestSeconds = trialSeconds
        End If

        AutoResultCount = AutoResultCount + 1
    Next trial

    PacketFileWriteEnabled = 1
    AutoTrialActive = 0
    Verbose = savedVerbose

    If bestIndex < 0 Then
        CompressionMethod = savedMethod
        Method7HashLength = savedHashLength
        RestoreBaseRanges baseRanges(), baseCount
        Exit Sub
    End If

    AutoResultWinner = bestIndex
    SetCompressionMethodFromName AutoResultName(bestIndex)
    RestoreBaseRanges baseRanges(), baseCount

    If savedVerbose > 0 Then
        Print "Auto winner: "; AutoResultName(bestIndex); " "; AutoResultBytes(bestIndex); " bytes "; FormatSeconds$(AutoResultSeconds(bestIndex)); "s"
    End If
End Sub

Function AutoCandidateBeatsBest (trialBytes As Long, trialSeconds As Double, bestBytes As Long, bestSeconds As Double, bestIndex As Long)
    If bestIndex < 0 Then
        AutoCandidateBeatsBest = 1
    ElseIf trialBytes < bestBytes - AUTO_TIE_BYTES Then
        AutoCandidateBeatsBest = 1
    ElseIf Abs(trialBytes - bestBytes) <= AUTO_TIE_BYTES And trialSeconds < bestSeconds Then
        AutoCandidateBeatsBest = 1
    Else
        AutoCandidateBeatsBest = 0
    End If
End Function

Sub RestoreBaseRanges (baseRanges() As RangeType, baseCount As Long)
    Dim i As Long
    If UBound(Ranges) < baseCount - 1 Then ReDim _Preserve Ranges(0 To baseCount + 1023) As RangeType
    For i = 0 To baseCount - 1
        Ranges(i) = baseRanges(i)
    Next i
    RangeCount = baseCount
End Sub

Sub BuildAutoCandidateSet (mode As Long)
    AutoCandidateCount = 0
    AddAutoCandidate 0, 0
    AddAutoCandidate 1, 0

    If mode = AUTO_FAST Then
        AddAutoCandidate 4, 0
        AddAutoCandidate 7, 8
        AddAutoCandidate 8, 32
        Exit Sub
    End If

    AddAutoCandidate 2, 0
    AddAutoCandidate 3, 0
    AddAutoCandidate 4, 0
    AddAutoCandidate 5, 0
    AddAutoCandidate 6, 0

    If mode = AUTO_ALL Then
        AddAutoCandidate 7, 5
        AddAutoCandidate 7, 6
    End If
    AddAutoCandidate 7, 8
    If mode = AUTO_ALL Then AddAutoCandidate 7, 12
    AddAutoCandidate 7, 16
    If mode = AUTO_ALL Then AddAutoCandidate 7, 24
    If mode = AUTO_BEST Or mode = AUTO_ALL Then AddAutoCandidate 7, 32
    If mode = AUTO_ALL Then
        AddAutoCandidate 7, 48
        AddAutoCandidate 7, 64
    End If

    If mode = AUTO_ALL Then
        AddAutoCandidate 8, 5
        AddAutoCandidate 8, 6
        AddAutoCandidate 8, 8
        AddAutoCandidate 8, 12
    End If
    If mode = AUTO_BEST Or mode = AUTO_ALL Then AddAutoCandidate 8, 16
    If mode = AUTO_ALL Then AddAutoCandidate 8, 24
    AddAutoCandidate 8, 32
    If mode = AUTO_ALL Then AddAutoCandidate 8, 48
    If mode = AUTO_BEST Or mode = AUTO_ALL Then AddAutoCandidate 8, 64

    AddAutoCandidate 9, 5
    If mode = AUTO_ALL Then AddAutoCandidate 9, 6
    If mode = AUTO_BEST Or mode = AUTO_ALL Then AddAutoCandidate 9, 8
    If mode = AUTO_ALL Then
        AddAutoCandidate 9, 12
        AddAutoCandidate 9, 16
    End If
End Sub

Sub AddAutoCandidate (method As Long, hashLen As Long)
    Dim i As Long
    For i = 0 To AutoCandidateCount - 1
        If AutoCandidateMethod(i) = method And AutoCandidateHash(i) = hashLen Then Exit Sub
    Next i
    If AutoCandidateCount > UBound(AutoCandidateMethod) Then
        ReDim _Preserve AutoCandidateMethod(0 To UBound(AutoCandidateMethod) + 64) As Long
        ReDim _Preserve AutoCandidateHash(0 To UBound(AutoCandidateHash) + 64) As Long
    End If
    AutoCandidateMethod(AutoCandidateCount) = method
    AutoCandidateHash(AutoCandidateCount) = hashLen
    AutoCandidateCount = AutoCandidateCount + 1
End Sub

Sub EnsureAutoResultCapacity (resultIndex As Long)
    If resultIndex > UBound(AutoResultName) Then
        ReDim _Preserve AutoResultName(0 To UBound(AutoResultName) + 64) As String
        ReDim _Preserve AutoResultBytes(0 To UBound(AutoResultBytes) + 64) As Long
        ReDim _Preserve AutoResultSeconds(0 To UBound(AutoResultSeconds) + 64) As Double
    End If
End Sub

Sub SetCompressionMethodFromName (methodTextName As String)
    If Left$(methodTextName, 3) = "-M7" Then
        CompressionMethod = 7
        Method7HashLength = Val(Mid$(methodTextName, 4))
    ElseIf Left$(methodTextName, 3) = "-M8" Then
        CompressionMethod = 8
        Method7HashLength = Val(Mid$(methodTextName, 4))
    ElseIf Left$(methodTextName, 3) = "-M9" Then
        CompressionMethod = 9
        Method7HashLength = Val(Mid$(methodTextName, 4))
    Else
        CompressionMethod = Val(Mid$(methodTextName, 3))
        Method7HashLength = 0
    End If
End Sub

Sub BuildCompressedPacketFile (BaseName As String)
    Dim packet As Long
    Dim compLen As Long
    Dim packetCountPos As Long
    Dim packetCount As Long
    Dim absAddr As Long
    Dim n As Long
    Dim outFile As String

    InitHash
    InitFileOut
    TotalLiteralBytes = 0
    TotalCopyBytes = 0
    TotalLiteralCommands = 0
    TotalCopyCommands = 0
    Method4FillBytes = 0
    Method4FillCommands = 0
    Method5PatternBytes = 0
    Method5PatternCommands = 0
    Method6Hash3Tests = 0
    Method6Hash4Tests = 0
    Method6OldSampleTests = 0
    Method6DuplicateSkips = 0
    Method7HashTests = 0
    Method8HashTests = 0

    OutString "CC3X03"
    packetCountPos = FileOutLen
    OutWord 0
    OutWord ExecuteAddr
    For n = 0 To 7
        OutByte PageBlock0(n)
    Next n
    For n = 0 To 7
        OutByte PageBlock1(n)
    Next n
    OutByte SourceWindowBlock
    OutByte DecodeSourceBlock
    OutByte &HFF
    OutByte &HFF
    OutByte ShadowCount
    For n = 0 To 4
        If n < ShadowCount Then
            OutByte Shadows(n).originalBlock
            OutByte Shadows(n).shadowBlock
        Else
            OutByte 0
            OutByte 0
        End If
    Next n
    OutWord FinalJumpAddr
    StreamHeaderLen = FileOutLen

    packetCount = 0
    For packet = 0 To RangeCount - 1
        absAddr = Ranges(packet).block * BLOCK_SIZE + Ranges(packet).offset
        compLen = CompressRange(absAddr, Ranges(packet).length)
        If VerifyCompressedRange(absAddr, Ranges(packet).length, compLen) = 0 Then
            Print "Internal error: compressed packet failed round-trip verification."
            Print "  block $"; Hex2$(Ranges(packet).block); " offset $"; Hex4$(Ranges(packet).offset); " length "; Ranges(packet).length
            System
        End If
        If compLen > BLOCK_SIZE Then
            Print "Internal warning: compressed packet is larger than 8K."
            Print "  block $"; Hex2$(Ranges(packet).block); " offset $"; Hex4$(Ranges(packet).offset); " length "; Ranges(packet).length; " comp "; compLen
        End If

        EnsurePacketTraceCapacity packetCount
        PacketStart(packetCount) = FileOutLen
        OutByte Ranges(packet).block
        OutWord Ranges(packet).offset
        OutWord Ranges(packet).length
        OutWord compLen
        For n = 0 To compLen - 1
            OutByte CompOut(n)
        Next n
        PacketLength(packetCount) = FileOutLen - PacketStart(packetCount)

        packetCount = packetCount + 1

        TotalLiteralBytes = TotalLiteralBytes + PacketLiteralBytes
        TotalCopyBytes = TotalCopyBytes + PacketCopyBytes
        TotalLiteralCommands = TotalLiteralCommands + PacketLiteralCommands
        TotalCopyCommands = TotalCopyCommands + PacketCopyCommands

        If Verbose > 0 And AutoTrialActive = 0 Then
            Print "Packet"; packetCount; " dst $"; Hex2$(Ranges(packet).block); ":$"; Hex4$(Ranges(packet).offset); " len"; Ranges(packet).length; " comp"; compLen
        End If
    Next packet

    PatchWord packetCountPos, packetCount

    If PacketFileWriteEnabled <> 0 Then
        outFile = BaseName + ".CC3X0"
        If _FileExists(outFile) Then Kill outFile
        WriteFileOut outFile
    End If
End Sub

Sub EnsurePacketTraceCapacity (packetIndex As Long)
    If packetIndex > UBound(PacketStart) Then
        ReDim _Preserve PacketStart(0 To UBound(PacketStart) + 1024) As Long
        ReDim _Preserve PacketLength(0 To UBound(PacketLength) + 1024) As Long
    End If
End Sub

Sub EnsureStreamChunkCapacity (chunkIndex As Long)
    If chunkIndex > UBound(StreamChunkStart) Then
        ReDim _Preserve StreamChunkStart(0 To UBound(StreamChunkStart) + 1024) As Long
        ReDim _Preserve StreamChunkBytes(0 To UBound(StreamChunkBytes) + 1024) As Long
        ReDim _Preserve StreamChunkFlags(0 To UBound(StreamChunkFlags) + 1024) As Long
        ReDim _Preserve StreamChunkDisk(0 To UBound(StreamChunkDisk) + 1024) As Long
    End If
End Sub

Sub BuildStreamingLoadFiles (BaseName As String)
    Dim packet As Long
    Dim chunkIndex As Long
    Dim chunkStart As Long
    Dim chunkLen As Long
    Dim recordLen As Long
    Dim chunkNeedsFinalMover As Long
    Dim recordNeedsFinalMover As Long
    Dim diskCount As Long

    If StreamHeaderLen <= 0 Or StreamHeaderLen > BLOCK_SIZE Then
        Print "Internal error: bad CC3X03 stream header length"; StreamHeaderLen
        System
    End If

    CleanupStreamChunks

    chunkIndex = 0
    chunkStart = 0
    chunkLen = StreamHeaderLen

    For packet = 0 To RangeCount - 1
        recordLen = PacketLength(packet)
        recordNeedsFinalMover = PacketNeedsFinalMover(packet)
        If recordLen <= 0 Then
            Print "Internal error: packet"; packet + 1; "has no recorded stream length."
            System
        End If
        If recordLen > BLOCK_SIZE Then
            Print "Packet"; packet + 1; "is too large for one 8K streaming chunk."
            Print "  record bytes:"; recordLen; " destination block $"; Hex2$(Ranges(packet).block); " offset $"; Hex4$(Ranges(packet).offset)
            Print "  Try a smaller -max value so the compressed packet can fit in one COMP####.BIN file."
            System
        End If

        If recordNeedsFinalMover <> 0 And chunkNeedsFinalMover = 0 And chunkLen > 0 Then
            WriteStreamChunk chunkIndex, chunkStart, chunkLen, 0
            chunkIndex = chunkIndex + 1
            chunkStart = PacketStart(packet)
            chunkLen = 0
        End If

        If chunkLen > 0 And chunkLen + recordLen > BLOCK_SIZE Then
            If chunkNeedsFinalMover <> 0 Then
                Print "Protected BASIC low-RAM final data does not fit in the last 8K streaming chunk."
                Print "  Reduce -max or improve compression so all protected packet records fit after the final mover."
                System
            End If
            WriteStreamChunk chunkIndex, chunkStart, chunkLen, 0
            chunkIndex = chunkIndex + 1
            chunkStart = PacketStart(packet)
            chunkLen = recordLen
            chunkNeedsFinalMover = 0
        Else
            If chunkLen = 0 Then chunkStart = PacketStart(packet)
            chunkLen = chunkLen + recordLen
        End If

        If recordNeedsFinalMover <> 0 Then chunkNeedsFinalMover = 1
    Next packet

    If chunkLen > 0 Then
        If chunkNeedsFinalMover <> 0 Then
            WriteStreamChunk chunkIndex, chunkStart, chunkLen, STREAM_CHUNK_FINAL
        Else
            WriteStreamChunk chunkIndex, chunkStart, chunkLen, 0
        End If
        chunkIndex = chunkIndex + 1
    End If

    StreamChunkCount = chunkIndex
    diskCount = AssignStreamDisks(chunkIndex)
    RewriteStreamChunks chunkIndex
    WriteStreamFileList chunkIndex
    WriteDiskFileList chunkIndex
    If Verbose > 0 Then Print "Streaming chunks:"; chunkIndex; "  disks:"; diskCount; "  status byte: $"; Hex4$(STREAM_STATUS_ADDR)
End Sub

Function PacketNeedsFinalMover (packetIndex As Long)
    If packetIndex < 0 Or packetIndex >= RangeCount Then
        PacketNeedsFinalMover = 0
    ElseIf IsFinalProtectedBlock(Ranges(packetIndex).block) <> 0 Then
        PacketNeedsFinalMover = 1
    Else
        PacketNeedsFinalMover = 0
    End If
End Function

Sub WriteStreamChunk (chunkIndex As Long, startPos As Long, byteCount As Long, flags As Long)
    Dim fileName As String

    If byteCount <= 0 Or byteCount > BLOCK_SIZE Then
        Print "Internal error: bad streaming chunk length"; byteCount
        System
    End If
    If startPos < 0 Or startPos + byteCount > FileOutLen Then
        Print "Internal error: streaming chunk points outside the CC3X03 file."
        System
    End If

    EnsureStreamChunkCapacity chunkIndex
    StreamChunkStart(chunkIndex) = startPos
    StreamChunkBytes(chunkIndex) = byteCount
    StreamChunkFlags(chunkIndex) = flags And &HFF

    fileName = ChunkFileName$(chunkIndex)
    InitDiskOut
    DiskAddFileOutLoadRecord SOURCE_WINDOW_ADDR, startPos, byteCount
    DiskStartLoadRecord STREAM_CHUNK_LENGTH_ADDR, 3
    DiskAddWord byteCount
    DiskAddByte StreamChunkFlags(chunkIndex)
    DiskAddExecRecord &H0F00
    WriteDiskOut fileName

    If Verbose > 0 Then Print "Chunk "; fileName; " stream offset $"; Hex$(startPos); " bytes"; byteCount
End Sub

Sub RewriteStreamChunks (chunkCount As Long)
    Dim i As Long
    Dim oldVerbose As Long

    oldVerbose = Verbose
    Verbose = 0
    For i = 0 To chunkCount - 1
        WriteStreamChunk i, StreamChunkStart(i), StreamChunkBytes(i), StreamChunkFlags(i)
    Next i
    Verbose = oldVerbose
End Sub

Function AssignStreamDisks (chunkCount As Long)
    Dim i As Long
    Dim diskNum As Long
    Dim usedGranules As Long
    Dim usedEntries As Long
    Dim chunkGranules As Long
    Dim chunkEntries As Long

    If chunkCount <= 0 Then
        AssignStreamDisks = 0
        Exit Function
    End If

    diskNum = 1
    usedGranules = Disk1BaseGranules
    usedEntries = Disk1BaseEntries

    For i = 0 To chunkCount - 1
        chunkGranules = GranulesForBytes(StreamChunkBytes(i) + STREAM_LOADM_OVERHEAD)
        chunkEntries = 1

        If chunkGranules > RSDOS_DISK_GRANULES Then
            Print "Chunk "; ChunkFileName$(i); " is too large for one RSDOS disk."
            System
        End If

        If usedGranules + chunkGranules > RSDOS_DISK_GRANULES Or usedEntries + chunkEntries > RSDOS_DIR_ENTRIES Then
            If i = 0 Then
                Print "The first streaming chunk does not fit on DISK1.DSK with START.BAS, MOVER.BIN, and CC3X0.BIN."
                System
            End If

            StreamChunkFlags(i - 1) = StreamChunkFlags(i - 1) Or STREAM_CHUNK_NEXT_DISK
            diskNum = diskNum + 1
            usedGranules = 0
            usedEntries = 0
        End If

        StreamChunkDisk(i) = diskNum
        usedGranules = usedGranules + chunkGranules
        usedEntries = usedEntries + chunkEntries
    Next i

    AssignStreamDisks = diskNum
End Function

Function Disk1BaseGranules
    Disk1BaseGranules = GranulesForFile("START.BAS") + GranulesForFile("MOVER_TEMPLATE.BIN") + GranulesForFile("CC3X0.BIN")
End Function

Function Disk1BaseEntries
    Disk1BaseEntries = 3
End Function

Function GranulesForFile (fileName As String)
    Dim f As Long
    Dim fileLen As Long

    If _FileExists(fileName) = 0 Then
        GranulesForFile = 1
        Exit Function
    End If

    f = FreeFile
    Open fileName For Binary As #f
    fileLen = LOF(f)
    Close #f
    GranulesForFile = GranulesForBytes(fileLen)
End Function

Function GranulesForBytes (byteCount As Long)
    If byteCount <= 0 Then
        GranulesForBytes = 0
    Else
        GranulesForBytes = (byteCount + RSDOS_GRANULE_BYTES - 1) \ RSDOS_GRANULE_BYTES
    End If
End Function

Sub WriteStreamFileList (chunkCount As Long)
    Dim f As Long
    Dim i As Long
    Dim lineText As String

    If _FileExists("STREAMFILES.LST") Then Kill "STREAMFILES.LST"
    f = FreeFile
    Open "STREAMFILES.LST" For Binary As #f
    For i = 0 To chunkCount - 1
        lineText = ChunkFileName$(i) + Chr$(10)
        Put #f, , lineText
    Next i
    Close #f
End Sub

Sub WriteDiskFileList (chunkCount As Long)
    Dim f As Long
    Dim i As Long
    Dim lineText As String

    If _FileExists("DISKFILES.LST") Then Kill "DISKFILES.LST"
    f = FreeFile
    Open "DISKFILES.LST" For Binary As #f
    For i = 0 To chunkCount - 1
        lineText = LTrim$(Str$(StreamChunkDisk(i))) + "," + ChunkFileName$(i) + Chr$(10)
        Put #f, , lineText
    Next i
    Close #f
End Sub

Sub CleanupStreamChunks
    Dim i As Long
    Dim fileName As String

    If _FileExists("STREAMFILES.LST") Then Kill "STREAMFILES.LST"
    If _FileExists("DISKFILES.LST") Then Kill "DISKFILES.LST"
    For i = 0 To 9999
        fileName = ChunkFileName$(i)
        If _FileExists(fileName) Then Kill fileName
    Next i
End Sub

Function ChunkFileName$ (chunkIndex As Long)
    If chunkIndex < 0 Or chunkIndex > 9999 Then
        Print "Too many streaming chunks.  COMP####.BIN only supports 0000-9999."
        System
    End If
    ChunkFileName$ = "COMP" + Right$("0000" + LTrim$(Str$(chunkIndex)), 4) + ".BIN"
End Function

Sub BuildPatchedMoverFile
    Dim templateName As String
    Dim outputName As String
    Dim f As Long
    Dim fileLen As Long
    Dim i As Long

    templateName = "MOVER_TEMPLATE.BIN"
    outputName = "MOVER.BIN"

    If _FileExists(templateName) = 0 Then
        Print "Can't find "; templateName; ".  Assemble CC3_Mover.asm before running CC3_Comp."
        System
    End If

    f = FreeFile
    Open templateName For Binary As #f
    fileLen = LOF(f)
    If fileLen <= 0 Then
        Close #f
        Print templateName; " is empty."
        System
    End If
    ReDim moverData(0 To fileLen - 1) As _Unsigned _Byte
    Get #f, , moverData()
    Close #f

    PatchLoadMByte moverData(), fileLen, MOVER_SHADOW_COUNT_ADDR, ShadowCount
    PatchLoadMByte moverData(), fileLen, MOVER_LOAD_BLOCK_ADDR, SourceWindowBlock
    PatchLoadMByte moverData(), fileLen, MOVER_DECODE_BLOCK_ADDR, DecodeSourceBlock

    For i = 0 To 4
        If i < ShadowCount Then
            PatchLoadMByte moverData(), fileLen, MOVER_SHADOW_PAIRS_ADDR + i * 2, Shadows(i).originalBlock
            PatchLoadMByte moverData(), fileLen, MOVER_SHADOW_PAIRS_ADDR + i * 2 + 1, Shadows(i).shadowBlock
        Else
            PatchLoadMByte moverData(), fileLen, MOVER_SHADOW_PAIRS_ADDR + i * 2, 0
            PatchLoadMByte moverData(), fileLen, MOVER_SHADOW_PAIRS_ADDR + i * 2 + 1, 0
        End If
    Next i

    If _FileExists(outputName) Then Kill outputName
    f = FreeFile
    Open outputName For Binary As #f
    Put #f, , moverData()
    Close #f
End Sub

Sub PatchLoadMByte (moverBytes() As _Unsigned _Byte, fileLen As Long, cpuAddr As Long, value As Long)
    Dim p As Long
    Dim marker As Long
    Dim recLen As Long
    Dim recAddr As Long
    Dim payloadStart As Long

    p = 0
    Do While p < fileLen
        marker = moverBytes(p): p = p + 1
        If marker = &HFF Then Exit Do
        If marker <> 0 Then
            Print "Corrupt MOVER_TEMPLATE.BIN record marker $"; Hex2$(marker)
            System
        End If
        If p + 3 >= fileLen Then
            Print "Corrupt MOVER_TEMPLATE.BIN data header."
            System
        End If
        recLen = moverBytes(p) * 256 + moverBytes(p + 1): p = p + 2
        recAddr = moverBytes(p) * 256 + moverBytes(p + 1): p = p + 2
        payloadStart = p

        If cpuAddr >= recAddr And cpuAddr < recAddr + recLen Then
            moverBytes(payloadStart + cpuAddr - recAddr) = value And &HFF
            Exit Sub
        End If

        p = payloadStart + recLen
    Loop

    Print "Could not patch MOVER_TEMPLATE.BIN address $"; Hex4$(cpuAddr)
    System
End Sub

Sub BuildSingleDiskLoadFile (BaseName As String)
    Dim packetLen As Long
    Dim sourceBlockCount As Long
    Dim sourceBlocks(0 To 127) As Long
    Dim i As Long
    Dim streamPos As Long
    Dim chunkLen As Long
    Dim blockNum As Long
    Dim loaderFile As String
    Dim f As Long
    Dim loaderLen As Long
    Dim p As Long
    Dim marker As Long
    Dim recLen As Long
    Dim recAddr As Long
    Dim payloadStart As Long
    Dim controlBytesWritten As Long

    packetLen = FileOutLen
    sourceBlockCount = (packetLen + BLOCK_SIZE - 1) \ BLOCK_SIZE
    If sourceBlockCount > 128 Then
        Print "Single-disk test loader can only handle 128 source blocks."
        System
    End If

    For i = 0 To sourceBlockCount - 1
        blockNum = FindFreeBlock
        If blockNum < 0 Then
            Print "Not enough free MMU blocks for compressed source stream."
            System
        End If
        BlockMap(blockNum) = BLOCK_SOURCE
        sourceBlocks(i) = blockNum
    Next i

    If Verbose > 0 Then
        Print "Compressed source blocks:";
        For i = 0 To sourceBlockCount - 1
            Print " $"; Hex2$(sourceBlocks(i));
        Next i
        Print
    End If

    ResolveLoadScreenBlocks sourceBlockCount

    InitDiskOut

    If ShowLoadScreenBlock(0) <> 0 Then DiskAddLoadScreenRecord 0
    DiskAddLoadProgressRecord 0, sourceBlockCount

    streamPos = 0
    For i = 0 To sourceBlockCount - 1
        chunkLen = packetLen - streamPos
        If chunkLen > BLOCK_SIZE Then chunkLen = BLOCK_SIZE

        If i > 0 And ShowLoadScreenBlock(i) <> 0 Then
            DiskAddLoadScreenRecord i
            DiskAddLoadProgressRecord i, sourceBlockCount
        End If

        DiskAddOneByteLoadRecord MMU0_START + 1, sourceBlocks(i) ' $FFA1
        DiskAddFileOutLoadRecord SOURCE_WINDOW_ADDR, streamPos, chunkLen
        streamPos = streamPos + chunkLen
        DiskAddLoadProgressRecord i + 1, sourceBlockCount
    Next i

    DiskStartLoadRecord LOADER_STAGE_BASE, LOADER_CONTROL_SIZE
    DiskAddByte sourceBlockCount
    controlBytesWritten = 1
    For i = 0 To 127
        If i < sourceBlockCount Then
            DiskAddByte sourceBlocks(i)
        Else
            DiskAddByte 0
        End If
        controlBytesWritten = controlBytesWritten + 1
    Next i
    DiskAddByte LoaderBlock
    controlBytesWritten = controlBytesWritten + 1
    Do While controlBytesWritten < LOADER_CONTROL_SIZE
        DiskAddByte 0
        controlBytesWritten = controlBytesWritten + 1
    Loop

    loaderFile = "CC3_NewLoaderCode3.BIN"
    If _FileExists(loaderFile) = 0 Then
        Print "Can't find loader binary: "; loaderFile
        System
    End If

    f = FreeFile
    Open loaderFile For Binary As #f
    loaderLen = LOF(f)
    ReDim LoaderData(0 To loaderLen - 1) As _Unsigned _Byte
    Get #f, , LoaderData()
    Close #f

    p = 0
    Do While p < loaderLen
        marker = LoaderData(p): p = p + 1
        If marker = &HFF Then Exit Do
        If marker <> 0 Then
            Print "Corrupt loader binary record marker $"; Hex2$(marker)
            System
        End If
        recLen = LoaderData(p) * 256 + LoaderData(p + 1): p = p + 2
        recAddr = LoaderData(p) * 256 + LoaderData(p + 1): p = p + 2
        payloadStart = p

        If recAddr >= LOADER_RUN_BASE Then recAddr = recAddr - LOADER_STAGE_DELTA

        DiskStartLoadRecord recAddr, recLen
        For i = 0 To recLen - 1
            DiskAddByte LoaderData(payloadStart + i)
        Next i
        p = payloadStart + recLen
    Loop

    DiskAddExecRecord &H0F00
    WriteDiskOut "DECOMP.BIN"
End Sub

Function CompressRange (absStart As Long, length As Long)
    Dim p As Long
    Dim literalStart As Long
    Dim literalLen As Long
    Dim curAbs As Long
    Dim bestSource As Long
    Dim bestLen As Long
    Dim useRepeat As Long
    Dim maxLen As Long
    Dim chosenLen As Long
    Dim chosenSource As Long
    Dim chosenScore As Long
    Dim nextSource As Long
    Dim nextLen As Long
    Dim nextUseRepeat As Long
    Dim nextScore As Long
    Dim fillLen As Long
    Dim fillScore As Long
    Dim patternLen As Long
    Dim patternRunLen As Long
    Dim patternScore As Long

    InitCompOut
    LastCopySource = -1
    PacketLiteralBytes = 0
    PacketCopyBytes = 0
    PacketLiteralCommands = 0
    PacketCopyCommands = 0

    p = 0
    literalStart = absStart
    literalLen = 0

    Do While p < length
        curAbs = absStart + p
        maxLen = length - p

        If CompressionMethod = 4 Or CompressionMethod = 5 Or CompressionMethod = 6 Or CompressionMethod = 7 Or CompressionMethod = 8 Or CompressionMethod = 9 Then
            fillLen = CountFillRun(curAbs, maxLen)
            If fillLen >= METHOD4_MIN_FILL_RUN Then
                SelectBestCopy curAbs, maxLen, chosenSource, chosenLen, useRepeat, chosenScore
                fillScore = FillRunRawSavings(fillLen)
                If chosenLen <= 0 Or fillScore > chosenScore Then
                    If literalLen > 0 Then
                        EmitLiteral literalStart, literalLen
                        literalLen = 0
                    End If

                    EmitLiteral curAbs, 1
                    AddDecodedBytes curAbs, 1
                    EmitCopyNew curAbs, fillLen - 1
                    LastCopySource = curAbs
                    AddDecodedBytes curAbs + 1, fillLen - 1
                    Method4FillBytes = Method4FillBytes + fillLen
                    Method4FillCommands = Method4FillCommands + 1

                    p = p + fillLen
                    literalStart = absStart + p
                    GoTo NextCompressLoop
                End If
            End If
        End If

        If CompressionMethod = 5 Or CompressionMethod = 6 Or CompressionMethod = 7 Or CompressionMethod = 8 Or CompressionMethod = 9 Then
            FindBestPatternRun curAbs, maxLen, patternLen, patternRunLen, patternScore
            If patternRunLen > patternLen Then
                SelectBestCopy curAbs, maxLen, chosenSource, chosenLen, useRepeat, chosenScore
                If chosenLen <= 0 Or patternScore > chosenScore Then
                    If literalLen > 0 Then
                        EmitLiteral literalStart, literalLen
                        literalLen = 0
                    End If

                    EmitLiteral curAbs, patternLen
                    AddDecodedBytes curAbs, patternLen
                    EmitCopyNew curAbs, patternRunLen - patternLen
                    LastCopySource = curAbs
                    AddDecodedBytes curAbs + patternLen, patternRunLen - patternLen
                    Method5PatternBytes = Method5PatternBytes + patternRunLen
                    Method5PatternCommands = Method5PatternCommands + 1

                    p = p + patternRunLen
                    literalStart = absStart + p
                    GoTo NextCompressLoop
                End If
            End If
        End If

        If CompressionMethod = 3 Then
            SelectBestCopyAdvanced curAbs, maxLen, chosenSource, chosenLen, useRepeat, chosenScore
        Else
            SelectBestCopy curAbs, maxLen, chosenSource, chosenLen, useRepeat, chosenScore

            If LazyMatching <> 0 And chosenLen > 0 And maxLen > 1 Then
                SelectBestCopy curAbs + 1, maxLen - 1, nextSource, nextLen, nextUseRepeat, nextScore
                If nextLen > 0 And nextScore > chosenScore + LAZY_SCORE_MARGIN Then chosenLen = 0
            End If
        End If

        If chosenLen > 0 Then
            If literalLen > 0 Then
                EmitLiteral literalStart, literalLen
                literalLen = 0
            End If

            If useRepeat <> 0 Then
                EmitCopyRepeat chosenLen
            Else
                EmitCopyNew chosenSource, chosenLen
                LastCopySource = chosenSource
            End If

            AddDecodedBytes curAbs, chosenLen
            p = p + chosenLen
            literalStart = absStart + p
        Else
            If literalLen = 0 Then literalStart = curAbs
            literalLen = literalLen + 1
            AddDecodedBytes curAbs, 1
            p = p + 1
        End If
NextCompressLoop:
    Loop

    If literalLen > 0 Then EmitLiteral literalStart, literalLen
    FlushCompBits
    CompressRange = CompOutLen
End Function

Sub SelectBestCopy (curAbs As Long, maxLen As Long, chosenSource As Long, chosenLen As Long, useRepeat As Long, chosenScore As Long)
    Dim bestSource As Long
    Dim bestLen As Long
    Dim repeatLen As Long
    Dim newScore As Long
    Dim repeatScore As Long

    FindBestMatch curAbs, maxLen, bestSource, bestLen

    repeatLen = 0
    If LastCopySource >= 0 Then
        repeatLen = CountMatch(LastCopySource, curAbs, maxLen)
    End If

    useRepeat = 0
    chosenLen = 0
    chosenSource = -1
    chosenScore = 0

    newScore = -2147483647
    repeatScore = -2147483647
    If bestLen >= MIN_NEW_MATCH Then
        ' Compare against literal bits.  A new-source copy has two control
        ' bits, an Elias length, and a 24-bit source block/offset address.
        newScore = bestLen * 8 - (2 + EliasBits(bestLen) + 24)
    End If
    If repeatLen >= MIN_REPEAT_MATCH Then
        ' A repeat-source copy only has two control bits and an Elias length,
        ' so it becomes worthwhile much sooner.
        repeatScore = repeatLen * 8 - (2 + EliasBits(repeatLen))
    End If

    If repeatScore > 0 Or newScore > 0 Then
        If repeatScore >= newScore Then
            useRepeat = 1
            chosenLen = repeatLen
            chosenScore = repeatScore
        Else
            useRepeat = 0
            chosenLen = bestLen
            chosenSource = bestSource
            chosenScore = newScore
        End If
    End If
End Sub

Function CountFillRun (absStart As Long, maxLen As Long)
    Dim value As Long
    Dim runLen As Long
    Dim blockRemaining As Long

    If maxLen <= 0 Then
        CountFillRun = 0
        Exit Function
    End If

    blockRemaining = BLOCK_SIZE - (absStart And &H1FFF)
    If maxLen > blockRemaining Then maxLen = blockRemaining

    value = Memory(absStart)
    runLen = 0
    Do While runLen < maxLen
        If Used(absStart + runLen) = 0 Then Exit Do
        If Memory(absStart + runLen) <> value Then Exit Do
        runLen = runLen + 1
    Loop

    CountFillRun = runLen
End Function

Function FillRunRawSavings (runLen As Long)
    Dim fillBits As Long
    If runLen < 2 Then
        FillRunRawSavings = -2147483647
        Exit Function
    End If

    ' One literal command for the seed byte, then a normal new-source copy from
    ' that just-written byte.  The 6809 decoder handles the overlap naturally.
    fillBits = 1 + EliasBits(1) + 8
    fillBits = fillBits + 2 + EliasBits(runLen - 1) + 24
    FillRunRawSavings = runLen * 8 - fillBits
End Function

Sub FindBestPatternRun (absStart As Long, maxLen As Long, bestPatternLen As Long, bestRunLen As Long, bestScore As Long)
    Dim patternLen As Long
    Dim runLen As Long
    Dim score As Long
    Dim minRun As Long

    bestPatternLen = 0
    bestRunLen = 0
    bestScore = 0

    patternLen = 2
    Do While patternLen <= METHOD5_MAX_PATTERN
        runLen = CountPatternRun(absStart, maxLen, patternLen)
        minRun = METHOD5_MIN_PATTERN_RUN
        If minRun < patternLen * 2 Then minRun = patternLen * 2
        If runLen >= minRun Then
            score = PatternRunRawSavings(runLen, patternLen)
            If score > bestScore Then
                bestPatternLen = patternLen
                bestRunLen = runLen
                bestScore = score
            End If
        End If
        patternLen = patternLen * 2
    Loop
End Sub

Function CountPatternRun (absStart As Long, maxLen As Long, patternLen As Long)
    Dim runLen As Long
    Dim blockRemaining As Long
    Dim i As Long

    If patternLen < 2 Then
        CountPatternRun = 0
        Exit Function
    End If

    blockRemaining = BLOCK_SIZE - (absStart And &H1FFF)
    If maxLen > blockRemaining Then maxLen = blockRemaining
    If maxLen < patternLen * 2 Then
        CountPatternRun = 0
        Exit Function
    End If

    For i = 0 To patternLen - 1
        If Used(absStart + i) = 0 Then
            CountPatternRun = 0
            Exit Function
        End If
    Next i

    runLen = patternLen
    Do While runLen < maxLen
        If Used(absStart + runLen) = 0 Then Exit Do
        If Memory(absStart + runLen) <> Memory(absStart + (runLen Mod patternLen)) Then Exit Do
        runLen = runLen + 1
    Loop

    CountPatternRun = runLen
End Function

Function PatternRunRawSavings (runLen As Long, patternLen As Long)
    Dim patternBits As Long
    If runLen <= patternLen Then
        PatternRunRawSavings = -2147483647
        Exit Function
    End If

    ' Emit the first full pattern as literals, then copy from that just-written
    ' pattern.  The normal overlapping-copy behavior repeats it for free.
    patternBits = 1 + EliasBits(patternLen) + patternLen * 8
    patternBits = patternBits + 2 + EliasBits(runLen - patternLen) + 24
    PatternRunRawSavings = runLen * 8 - patternBits
End Function

Sub SelectBestCopyAdvanced (curAbs As Long, maxLen As Long, chosenSource As Long, chosenLen As Long, useRepeat As Long, chosenScore As Long)
    Dim candType(0 To METHOD3_MAX_CANDIDATES - 1) As Long
    Dim candSource(0 To METHOD3_MAX_CANDIDATES - 1) As Long
    Dim candLen(0 To METHOD3_MAX_CANDIDATES - 1) As Long
    Dim candCount As Long
    Dim i As Long
    Dim bestIndex As Long
    Dim bestCost As Long
    Dim thisCost As Long
    Dim nextLast As Long
    Dim safeSource As Long
    Dim safeLen As Long
    Dim safeRepeat As Long
    Dim safeScore As Long
    Dim nextSource As Long
    Dim nextLen As Long
    Dim nextRepeat As Long
    Dim nextScore As Long

    SelectBestCopy curAbs, maxLen, safeSource, safeLen, safeRepeat, safeScore
    If LazyMatching <> 0 And safeLen > 0 And maxLen > 1 Then
        SelectBestCopy curAbs + 1, maxLen - 1, nextSource, nextLen, nextRepeat, nextScore
        If nextLen > 0 And nextScore > safeScore + LAZY_SCORE_MARGIN Then safeLen = 0
    End If

    BuildAdvancedCandidates curAbs, maxLen, LastCopySource, curAbs, curAbs, candType(), candSource(), candLen(), candCount

    bestIndex = 0
    bestCost = 2147483647
    For i = 0 To candCount - 1
        nextLast = AdvancedNextLast(candType(i), candSource(i), LastCopySource)
        thisCost = AdvancedCommandBits(candType(i), candLen(i))
        thisCost = thisCost + AdvancedLookaheadCost(curAbs + candLen(i), maxLen - candLen(i), nextLast, curAbs, curAbs + candLen(i), METHOD3_PARSE_DEPTH - 1)
        If thisCost < bestCost Then
            bestCost = thisCost
            bestIndex = i
        End If
    Next i

    ' M3 is allowed to find better local/overlap choices, but it should not
    ' throw away a known-good greedy copy for a shorter speculative command.
    If safeLen > 0 Then
        If candType(bestIndex) = 0 Or candLen(bestIndex) < safeLen Then
            chosenSource = safeSource
            chosenLen = safeLen
            useRepeat = safeRepeat
            chosenScore = safeScore
            Exit Sub
        End If
        If AdvancedCommandSavings(candType(bestIndex), candLen(bestIndex)) < AdvancedCommandSavings(1 + safeRepeat, safeLen) + 16 Then
            chosenSource = safeSource
            chosenLen = safeLen
            useRepeat = safeRepeat
            chosenScore = safeScore
            Exit Sub
        End If
    End If

    chosenScore = -bestCost
    If candType(bestIndex) = 0 Then
        chosenSource = -1
        chosenLen = 0
        useRepeat = 0
    ElseIf candType(bestIndex) = 2 Then
        chosenSource = -1
        chosenLen = candLen(bestIndex)
        useRepeat = 1
    Else
        chosenSource = candSource(bestIndex)
        chosenLen = candLen(bestIndex)
        useRepeat = 0
    End If
End Sub

Function AdvancedLookaheadCost (destAbs As Long, maxLen As Long, simLast As Long, simBaseAbs As Long, simEndAbs As Long, depth As Long)
    Dim candType(0 To METHOD3_MAX_CANDIDATES - 1) As Long
    Dim candSource(0 To METHOD3_MAX_CANDIDATES - 1) As Long
    Dim candLen(0 To METHOD3_MAX_CANDIDATES - 1) As Long
    Dim candCount As Long
    Dim i As Long
    Dim bestCost As Long
    Dim thisCost As Long
    Dim nextLast As Long

    If maxLen <= 0 Then
        AdvancedLookaheadCost = 0
        Exit Function
    End If

    If depth <= 0 Then
        AdvancedLookaheadCost = AdvancedTailBits(maxLen)
        Exit Function
    End If

    BuildAdvancedCandidates destAbs, maxLen, simLast, simBaseAbs, simEndAbs, candType(), candSource(), candLen(), candCount

    bestCost = 2147483647
    For i = 0 To candCount - 1
        nextLast = AdvancedNextLast(candType(i), candSource(i), simLast)
        thisCost = AdvancedCommandBits(candType(i), candLen(i))
        thisCost = thisCost + AdvancedLookaheadCost(destAbs + candLen(i), maxLen - candLen(i), nextLast, simBaseAbs, destAbs + candLen(i), depth - 1)
        If thisCost < bestCost Then bestCost = thisCost
    Next i

    AdvancedLookaheadCost = bestCost
End Function

Sub BuildAdvancedCandidates (destAbs As Long, maxLen As Long, simLast As Long, simBaseAbs As Long, simEndAbs As Long, candType() As Long, candSource() As Long, candLen() As Long, candCount As Long)
    Dim bestSource As Long
    Dim bestLen As Long
    Dim repeatLen As Long
    Dim localSource As Long
    Dim localLen As Long
    Dim dist As Long
    Dim thisSource As Long
    Dim thisLen As Long

    candCount = 0
    AddAdvancedCandidate candType(), candSource(), candLen(), candCount, 0, -1, 1

    FindBestMatchAdvanced destAbs, maxLen, simBaseAbs, simEndAbs, bestSource, bestLen
    If bestLen >= MIN_NEW_MATCH Then AddAdvancedMatchVariants candType(), candSource(), candLen(), candCount, 1, bestSource, bestLen, MIN_NEW_MATCH

    If simLast >= 0 Then
        repeatLen = CountMatchAdvanced(simLast, destAbs, maxLen, simBaseAbs, simEndAbs)
        If repeatLen >= MIN_REPEAT_MATCH Then AddAdvancedMatchVariants candType(), candSource(), candLen(), candCount, 2, simLast, repeatLen, MIN_REPEAT_MATCH
    End If

    localSource = -1
    localLen = 0
    For dist = 1 To METHOD3_LOCAL_SCAN
        thisSource = destAbs - dist
        If thisSource >= 0 Then
            thisLen = CountMatchAdvanced(thisSource, destAbs, maxLen, simBaseAbs, simEndAbs)
            If thisLen > localLen Then
                localLen = thisLen
                localSource = thisSource
            End If
        End If
    Next dist
    If localLen >= MIN_NEW_MATCH Then AddAdvancedMatchVariants candType(), candSource(), candLen(), candCount, 1, localSource, localLen, MIN_NEW_MATCH
End Sub

Sub AddAdvancedMatchVariants (candType() As Long, candSource() As Long, candLen() As Long, candCount As Long, commandType As Long, sourceAbs As Long, fullLen As Long, minLen As Long)
    Dim halfLen As Long
    Dim shortLen As Long

    AddAdvancedCandidate candType(), candSource(), candLen(), candCount, commandType, sourceAbs, fullLen

    If fullLen > minLen Then AddAdvancedCandidate candType(), candSource(), candLen(), candCount, commandType, sourceAbs, minLen

    halfLen = fullLen \ 2
    If halfLen >= minLen And halfLen <> fullLen Then AddAdvancedCandidate candType(), candSource(), candLen(), candCount, commandType, sourceAbs, halfLen

    shortLen = fullLen - 1
    If shortLen >= minLen Then AddAdvancedCandidate candType(), candSource(), candLen(), candCount, commandType, sourceAbs, shortLen
End Sub

Sub AddAdvancedCandidate (candType() As Long, candSource() As Long, candLen() As Long, candCount As Long, commandType As Long, sourceAbs As Long, length As Long)
    Dim i As Long

    If length <= 0 Then Exit Sub
    If candCount > UBound(candType) Then Exit Sub

    For i = 0 To candCount - 1
        If candType(i) = commandType And candSource(i) = sourceAbs And candLen(i) = length Then Exit Sub
    Next i

    candType(candCount) = commandType
    candSource(candCount) = sourceAbs
    candLen(candCount) = length
    candCount = candCount + 1
End Sub

Function AdvancedNextLast (commandType As Long, sourceAbs As Long, simLast As Long)
    If commandType = 1 Then
        AdvancedNextLast = sourceAbs
    Else
        AdvancedNextLast = simLast
    End If
End Function

Function AdvancedCommandBits (commandType As Long, length As Long)
    If commandType = 0 Then
        AdvancedCommandBits = length * 8 + 2
    ElseIf commandType = 1 Then
        AdvancedCommandBits = 2 + EliasBits(length) + 24
    Else
        AdvancedCommandBits = 2 + EliasBits(length)
    End If
End Function

Function AdvancedCommandSavings (commandType As Long, length As Long)
    AdvancedCommandSavings = length * 8 - AdvancedCommandBits(commandType, length)
End Function

Function AdvancedTailBits (length As Long)
    AdvancedTailBits = length * 8 + 2
End Function

Sub FindBestMatchAdvanced (curAbs As Long, maxLen As Long, simBaseAbs As Long, simEndAbs As Long, bestSource As Long, bestLen As Long)
    Dim hash As Long
    Dim candidate As Long
    Dim checks As Long
    Dim thisLen As Long

    bestSource = -1
    bestLen = 0

    If maxLen < 3 Then Exit Sub
    If CanInputHashAt(curAbs) = 0 Then Exit Sub

    hash = HashAt(curAbs)
    candidate = HashHead(hash)
    checks = 0
    Do While candidate >= 0 And checks < METHOD3_CHAIN_CHECKS
        thisLen = CountMatchAdvanced(candidate, curAbs, maxLen, simBaseAbs, simEndAbs)
        If thisLen > bestLen Then
            bestLen = thisLen
            bestSource = candidate
        End If
        candidate = HashNext(candidate)
        checks = checks + 1
    Loop
End Sub

Function CountMatchAdvanced (sourceAbs As Long, destAbs As Long, maxLen As Long, simBaseAbs As Long, simEndAbs As Long)
    Dim l As Long
    Dim sourceOffset As Long
    Dim sourceByte As Long

    sourceOffset = sourceAbs And &H1FFF
    If maxLen > BLOCK_SIZE - sourceOffset Then maxLen = BLOCK_SIZE - sourceOffset

    l = 0
    Do While l < maxLen
        sourceByte = sourceAbs + l
        If SourceByteAvailableAdvanced(sourceByte, destAbs, l, simBaseAbs, simEndAbs) = 0 Then Exit Do
        If Memory(sourceByte) <> Memory(destAbs + l) Then Exit Do
        l = l + 1
    Loop

    CountMatchAdvanced = l
End Function

Function SourceByteAvailableAdvanced (sourceByte As Long, destAbs As Long, copyIndex As Long, simBaseAbs As Long, simEndAbs As Long)
    If sourceByte < 0 Or sourceByte >= MEM_SIZE Then
        SourceByteAvailableAdvanced = 0
        Exit Function
    End If

    If Decoded(sourceByte) <> 0 Then
        SourceByteAvailableAdvanced = 1
        Exit Function
    End If

    If Used(sourceByte) <> 0 And sourceByte >= simBaseAbs And sourceByte < simEndAbs Then
        SourceByteAvailableAdvanced = 1
        Exit Function
    End If

    If sourceByte >= destAbs And sourceByte < destAbs + copyIndex Then
        SourceByteAvailableAdvanced = 1
    Else
        SourceByteAvailableAdvanced = 0
    End If
End Function

Sub EmitLiteral (absStart As Long, length As Long)
    Dim i As Long
    CompWriteBit 0
    CompWriteElias length
    For i = 0 To length - 1
        CompWriteByte Memory(absStart + i)
    Next i
    PacketLiteralBytes = PacketLiteralBytes + length
    PacketLiteralCommands = PacketLiteralCommands + 1
End Sub

Sub EmitCopyNew (sourceAbs As Long, length As Long)
    Dim sourceBlock As Long
    Dim sourceOffset As Long
    CompWriteBit 1
    CompWriteBit 1
    CompWriteElias length
    sourceBlock = sourceAbs \ BLOCK_SIZE
    sourceOffset = sourceAbs And &H1FFF
    CompWriteByte sourceBlock
    CompWriteByte sourceOffset \ 256
    CompWriteByte sourceOffset And &HFF
    PacketCopyBytes = PacketCopyBytes + length
    PacketCopyCommands = PacketCopyCommands + 1
End Sub

Sub EmitCopyRepeat (length As Long)
    CompWriteBit 1
    CompWriteBit 0
    CompWriteElias length
    PacketCopyBytes = PacketCopyBytes + length
    PacketCopyCommands = PacketCopyCommands + 1
End Sub

Sub FindBestMatch (curAbs As Long, maxLen As Long, bestSource As Long, bestLen As Long)
    Dim hash As Long
    Dim candidate As Long
    Dim checks As Long
    Dim thisLen As Long

    If CompressionMethod = 6 Or CompressionMethod = 7 Or CompressionMethod = 8 Or CompressionMethod = 9 Then
        FindBestMatchWide curAbs, maxLen, bestSource, bestLen
        Exit Sub
    End If

    bestSource = -1
    bestLen = 0

    If maxLen < 3 Then Exit Sub
    If CanInputHashAt(curAbs) = 0 Then Exit Sub

    hash = HashAt(curAbs)
    candidate = HashHead(hash)
    checks = 0
    Do While candidate >= 0 And checks < MaxChainChecks
        thisLen = CountMatch(candidate, curAbs, maxLen)
        If thisLen > bestLen Then
            bestLen = thisLen
            bestSource = candidate
        End If
        candidate = HashNext(candidate)
        checks = checks + 1
    Loop
End Sub

Sub FindBestMatchWide (curAbs As Long, maxLen As Long, bestSource As Long, bestLen As Long)
    Dim seen(0 To METHOD6_SEEN_CANDIDATES - 1) As Long
    Dim seenCount As Long
    Dim chainLimit As Long
    Dim hash As Long
    Dim usedHash4 As Long
    Dim usedHashN As Long
    Dim hashLen As Long
    Dim inputMaxLen As Long

    bestSource = -1
    bestLen = 0
    seenCount = 0
    usedHash4 = 0
    usedHashN = 0

    If maxLen < 3 Then Exit Sub

    chainLimit = MaxChainChecks * METHOD6_CHAIN_MULTIPLIER
    If chainLimit < MaxChainChecks Then chainLimit = MaxChainChecks
    If chainLimit > METHOD6_MAX_CHAIN_CHECKS Then chainLimit = METHOD6_MAX_CHAIN_CHECKS

    If CompressionMethod = 9 Then
        inputMaxLen = BuildMethod8InputHashes(curAbs, maxLen)
        If inputMaxLen > Method7HashLength Then inputMaxLen = Method7HashLength

        If CanInputHash4At(curAbs) <> 0 Then
            hash = Hash4At(curAbs)
            SearchMatchChain curAbs, maxLen, Hash4Head(hash), 4, chainLimit, bestSource, bestLen, seen(), seenCount
            usedHash4 = 1
        End If

        For hashLen = METHOD8_EXTRA_MIN_HASH_LENGTH To inputMaxLen
            hash = Method8InputHash(hashLen)
            SearchMatchChainM8 curAbs, maxLen, hashLen, HashM8Head(Method8HeadIndex(hashLen, hash)), chainLimit, bestSource, bestLen, seen(), seenCount
            If bestLen = maxLen Then Exit For
        Next hashLen

        If bestLen < MIN_NEW_MATCH And CanInputHashAt(curAbs) <> 0 Then
            hash = HashAt(curAbs)
            SearchMatchChain curAbs, maxLen, HashHead(hash), 3, chainLimit, bestSource, bestLen, seen(), seenCount
        End If
        Exit Sub
    End If

    If CompressionMethod = 8 Then
        inputMaxLen = BuildMethod8InputHashes(curAbs, maxLen)
        If inputMaxLen > Method7HashLength Then inputMaxLen = Method7HashLength

        For hashLen = inputMaxLen To METHOD8_EXTRA_MIN_HASH_LENGTH Step -1
            hash = Method8InputHash(hashLen)
            SearchMatchChainM8 curAbs, maxLen, hashLen, HashM8Head(Method8HeadIndex(hashLen, hash)), chainLimit, bestSource, bestLen, seen(), seenCount
            If bestLen >= hashLen Then Exit For
        Next hashLen

        If bestLen < MIN_NEW_MATCH And CanInputHash4At(curAbs) <> 0 Then
            hash = Hash4At(curAbs)
            SearchMatchChain curAbs, maxLen, Hash4Head(hash), 4, chainLimit, bestSource, bestLen, seen(), seenCount
            usedHash4 = 1
        End If

        If usedHash4 = 0 And bestLen < MIN_NEW_MATCH And CanInputHashAt(curAbs) <> 0 Then
            hash = HashAt(curAbs)
            SearchMatchChain curAbs, maxLen, HashHead(hash), 3, chainLimit, bestSource, bestLen, seen(), seenCount
        End If
        Exit Sub
    End If

    If CompressionMethod = 7 And CanInputHashNAt(curAbs) <> 0 Then
        hash = HashNAt(curAbs)
        SearchMatchChain curAbs, maxLen, HashNHead(hash), 7, chainLimit, bestSource, bestLen, seen(), seenCount
        usedHashN = 1
    End If

    If (usedHashN = 0 Or bestLen < Method7HashLength) And CanInputHash4At(curAbs) <> 0 Then
        hash = Hash4At(curAbs)
        SearchMatchChain curAbs, maxLen, Hash4Head(hash), 4, chainLimit, bestSource, bestLen, seen(), seenCount
        usedHash4 = 1
    End If

    If usedHashN = 0 And usedHash4 = 0 And CanInputHashAt(curAbs) <> 0 Then
        hash = HashAt(curAbs)
        SearchMatchChain curAbs, maxLen, HashHead(hash), 3, chainLimit, bestSource, bestLen, seen(), seenCount
    End If
End Sub

Sub SearchMatchChainM8 (curAbs As Long, maxLen As Long, hashLen As Long, firstCandidatePacked As Long, chainLimit As Long, bestSource As Long, bestLen As Long, seen() As Long, seenCount As Long)
    Dim candidatePacked As Long
    Dim candidate As Long
    Dim chainPos As Long
    Dim oldSamples As Long
    Dim testCandidate As Long
    Dim thisLen As Long

    candidatePacked = firstCandidatePacked
    chainPos = 0
    oldSamples = 0

    Do While candidatePacked > 0
        testCandidate = 0
        If chainPos < chainLimit Then
            testCandidate = 1
        ElseIf oldSamples < METHOD6_OLD_SAMPLE_LIMIT Then
            If chainPos Mod METHOD6_OLD_SAMPLE_STRIDE = 0 Then
                testCandidate = 1
                oldSamples = oldSamples + 1
                Method6OldSampleTests = Method6OldSampleTests + 1
            End If
        Else
            Exit Do
        End If

        candidate = candidatePacked - 1
        If testCandidate <> 0 Then
            If CandidateAlreadySeen(candidate, seen(), seenCount) = 0 Then
                RememberCandidate candidate, seen(), seenCount
                thisLen = CountMatch(candidate, curAbs, maxLen)
                Method8HashTests = Method8HashTests + 1
                If thisLen > bestLen Then
                    bestLen = thisLen
                    bestSource = candidate
                    If bestLen = maxLen Then Exit Do
                End If
            Else
                Method6DuplicateSkips = Method6DuplicateSkips + 1
            End If
        End If

        candidatePacked = HashM8Next(Method8NextIndex(hashLen, candidate))
        chainPos = chainPos + 1
    Loop
End Sub

Sub SearchMatchChain (curAbs As Long, maxLen As Long, firstCandidate As Long, hashMode As Long, chainLimit As Long, bestSource As Long, bestLen As Long, seen() As Long, seenCount As Long)
    Dim candidate As Long
    Dim chainPos As Long
    Dim oldSamples As Long
    Dim testCandidate As Long
    Dim thisLen As Long

    candidate = firstCandidate
    chainPos = 0
    oldSamples = 0

    Do While candidate >= 0
        testCandidate = 0
        If chainPos < chainLimit Then
            testCandidate = 1
        ElseIf oldSamples < METHOD6_OLD_SAMPLE_LIMIT Then
            If chainPos Mod METHOD6_OLD_SAMPLE_STRIDE = 0 Then
                testCandidate = 1
                oldSamples = oldSamples + 1
                Method6OldSampleTests = Method6OldSampleTests + 1
            End If
        Else
            Exit Do
        End If

        If testCandidate <> 0 Then
            If CandidateAlreadySeen(candidate, seen(), seenCount) = 0 Then
                RememberCandidate candidate, seen(), seenCount
                thisLen = CountMatch(candidate, curAbs, maxLen)
                If hashMode = 7 Then
                    Method7HashTests = Method7HashTests + 1
                ElseIf hashMode = 4 Then
                    Method6Hash4Tests = Method6Hash4Tests + 1
                Else
                    Method6Hash3Tests = Method6Hash3Tests + 1
                End If
                If thisLen > bestLen Then
                    bestLen = thisLen
                    bestSource = candidate
                    If bestLen = maxLen Then Exit Do
                End If
            Else
                Method6DuplicateSkips = Method6DuplicateSkips + 1
            End If
        End If

        If hashMode = 7 Then
            candidate = HashNNext(candidate)
        ElseIf hashMode = 4 Then
            candidate = Hash4Next(candidate)
        Else
            candidate = HashNext(candidate)
        End If
        chainPos = chainPos + 1
    Loop
End Sub

Sub InitMethod8Hash
    Dim hashCount As Long
    Dim headCount As Long
    Dim nextCount As Long

    If (CompressionMethod <> 8 And CompressionMethod <> 9) Or Method7HashLength < METHOD8_EXTRA_MIN_HASH_LENGTH Then
        ReDim HashM8Head(0 To 0) As Long
        ReDim HashM8Next(0 To 0) As Long
        ReDim HashedM8(0 To 0) As _Unsigned _Byte
        Exit Sub
    End If

    hashCount = Method7HashLength - METHOD8_EXTRA_MIN_HASH_LENGTH + 1
    headCount = hashCount * HASH_SIZE
    nextCount = hashCount * MEM_SIZE

    ReDim HashM8Head(0 To headCount - 1) As Long
    ReDim HashM8Next(0 To nextCount - 1) As Long
    ReDim HashedM8(0 To nextCount - 1) As _Unsigned _Byte
End Sub

Sub AddMethod8Hashes (absAddr As Long)
    Dim maxLen As Long
    Dim hashLen As Long
    Dim h As Long
    Dim nextIndex As Long
    Dim headIndex As Long

    If Method7HashLength < METHOD8_EXTRA_MIN_HASH_LENGTH Then Exit Sub
    If absAddr < 0 Or absAddr >= MEM_SIZE Then Exit Sub

    maxLen = Method7HashLength
    If maxLen > MEM_SIZE - absAddr Then maxLen = MEM_SIZE - absAddr
    If maxLen > BLOCK_SIZE - (absAddr And &H1FFF) Then maxLen = BLOCK_SIZE - (absAddr And &H1FFF)

    h = 0
    For hashLen = 1 To maxLen
        If Used(absAddr + hashLen - 1) = 0 Or Decoded(absAddr + hashLen - 1) = 0 Then Exit For
        h = ((h * 257) Xor CLng(Memory(absAddr + hashLen - 1))) And (HASH_SIZE - 1)
        If hashLen >= METHOD8_EXTRA_MIN_HASH_LENGTH Then
            nextIndex = Method8NextIndex(hashLen, absAddr)
            If HashedM8(nextIndex) = 0 Then
                headIndex = Method8HeadIndex(hashLen, h)
                HashM8Next(nextIndex) = HashM8Head(headIndex)
                HashM8Head(headIndex) = absAddr + 1
                HashedM8(nextIndex) = 1
            End If
        End If
    Next hashLen
End Sub

Function BuildMethod8InputHashes (absAddr As Long, requestedMax As Long)
    Dim maxLen As Long
    Dim hashLen As Long
    Dim h As Long

    If Method7HashLength < METHOD7_MIN_HASH_LENGTH Then
        BuildMethod8InputHashes = 0
        Exit Function
    End If
    If absAddr < 0 Or absAddr >= MEM_SIZE Then
        BuildMethod8InputHashes = 0
        Exit Function
    End If

    maxLen = Method7HashLength
    If maxLen > requestedMax Then maxLen = requestedMax
    If maxLen > MEM_SIZE - absAddr Then maxLen = MEM_SIZE - absAddr
    If maxLen > BLOCK_SIZE - (absAddr And &H1FFF) Then maxLen = BLOCK_SIZE - (absAddr And &H1FFF)

    h = 0
    For hashLen = 1 To maxLen
        If Used(absAddr + hashLen - 1) = 0 Then Exit For
        h = ((h * 257) Xor CLng(Memory(absAddr + hashLen - 1))) And (HASH_SIZE - 1)
        If hashLen <= METHOD7_MAX_HASH_LENGTH Then Method8InputHash(hashLen) = h
    Next hashLen

    BuildMethod8InputHashes = hashLen - 1
End Function

Function Method8HeadIndex (hashLen As Long, hashValue As Long)
    Method8HeadIndex = (hashLen - METHOD8_EXTRA_MIN_HASH_LENGTH) * HASH_SIZE + hashValue
End Function

Function Method8NextIndex (hashLen As Long, absAddr As Long)
    Method8NextIndex = (hashLen - METHOD8_EXTRA_MIN_HASH_LENGTH) * MEM_SIZE + absAddr
End Function

Function CandidateAlreadySeen (candidate As Long, seen() As Long, seenCount As Long)
    Dim i As Long
    For i = 0 To seenCount - 1
        If seen(i) = candidate Then
            CandidateAlreadySeen = 1
            Exit Function
        End If
    Next i
    CandidateAlreadySeen = 0
End Function

Sub RememberCandidate (candidate As Long, seen() As Long, seenCount As Long)
    If seenCount > UBound(seen) Then Exit Sub
    seen(seenCount) = candidate
    seenCount = seenCount + 1
End Sub

Function OptionNumber (Arg As String, PrefixLen As Long)
    Dim text As String
    text = Mid$(Arg, PrefixLen + 1)
    If Left$(text, 1) = "=" Then text = Mid$(text, 2)
    OptionNumber = Val(text)
End Function

Function HexByteOption (text As String)
    Dim i As Long
    Dim ch As String
    Dim value As Long
    Dim digit As Long

    text = UCase$(text)
    If Left$(text, 1) = "=" Then text = Mid$(text, 2)
    If text = "" Then
        HexByteOption = 0
        Exit Function
    End If
    If Len(text) > 2 Then
        HexByteOption = -1
        Exit Function
    End If

    value = 0
    For i = 1 To Len(text)
        ch = Mid$(text, i, 1)
        If ch >= "0" And ch <= "9" Then
            digit = Asc(ch) - Asc("0")
        ElseIf ch >= "A" And ch <= "F" Then
            digit = Asc(ch) - Asc("A") + 10
        Else
            HexByteOption = -1
            Exit Function
        End If
        value = value * 16 + digit
    Next i

    If value < 0 Or value > 255 Then
        HexByteOption = -1
    Else
        HexByteOption = value
    End If
End Function

Function MethodName$
    If CompressionMethod = 7 Then
        MethodName$ = "-M7" + LTrim$(Str$(Method7HashLength))
    ElseIf CompressionMethod = 8 Then
        MethodName$ = "-M8" + LTrim$(Str$(Method7HashLength))
    ElseIf CompressionMethod = 9 Then
        MethodName$ = "-M9" + LTrim$(Str$(Method7HashLength))
    Else
        MethodName$ = "-M" + LTrim$(Str$(CompressionMethod))
    End If
End Function

Function AutoModeName$
    If AutoMode = AUTO_FAST Then
        AutoModeName$ = "-Afast"
    ElseIf AutoMode = AUTO_BEST Then
        AutoModeName$ = "-Abest"
    ElseIf AutoMode = AUTO_ALL Then
        AutoModeName$ = "-Aall"
    ElseIf AutoMode = AUTO_BALANCED Then
        AutoModeName$ = "-A"
    Else
        AutoModeName$ = "off"
    End If
End Function

Function FormatSeconds$ (seconds As Double)
    FormatSeconds$ = LTrim$(Str$(Int(seconds * 100 + .5) / 100))
End Function

Function FormatPercent$ (savedBytes As Long, baseBytes As Long)
    Dim pctTimes100 As Long
    Dim whole As Long
    Dim frac As Long
    Dim signText As String

    If baseBytes <= 0 Then
        FormatPercent$ = "n/a"
        Exit Function
    End If

    signText = ""
    If savedBytes < 0 Then signText = "-"
    pctTimes100 = Int(Abs(CDbl(savedBytes) * 10000# / CDbl(baseBytes)) + .5)
    whole = pctTimes100 \ 100
    frac = pctTimes100 Mod 100
    FormatPercent$ = signText + LTrim$(Str$(whole)) + "." + Right$("00" + LTrim$(Str$(frac)), 2) + "%"
End Function

Function CountMatch (sourceAbs As Long, destAbs As Long, maxLen As Long)
    Dim l As Long
    Dim sourceOffset As Long
    Dim sourceByte As Long

    sourceOffset = sourceAbs And &H1FFF
    If maxLen > BLOCK_SIZE - sourceOffset Then maxLen = BLOCK_SIZE - sourceOffset

    l = 0
    Do While l < maxLen
        sourceByte = sourceAbs + l
        If SourceByteAvailable(sourceByte, destAbs, l) = 0 Then Exit Do
        If Memory(sourceByte) <> Memory(destAbs + l) Then Exit Do
        l = l + 1
    Loop

    CountMatch = l
End Function

Function SourceByteAvailable (sourceByte As Long, destAbs As Long, copyIndex As Long)
    If sourceByte < 0 Or sourceByte >= MEM_SIZE Then
        SourceByteAvailable = 0
        Exit Function
    End If

    If Decoded(sourceByte) <> 0 Then
        SourceByteAvailable = 1
        Exit Function
    End If

    ' Allow ordinary forward-overlap copies, but only for bytes that the same
    ' copy command would already have produced earlier in the destination.
    If sourceByte >= destAbs And sourceByte < destAbs + copyIndex Then
        SourceByteAvailable = 1
    Else
        SourceByteAvailable = 0
    End If
End Function

Sub AddDecodedBytes (absStart As Long, length As Long)
    Dim i As Long
    Dim a As Long
    Dim firstBack As Long
    For i = 0 To length - 1
        Decoded(absStart + i) = 1
    Next i

    firstBack = -3
    If CompressionMethod = 7 Or CompressionMethod = 8 Or CompressionMethod = 9 Then firstBack = -(Method7HashLength - 1)
    For i = firstBack To length - 1
        a = absStart + i
        If CanHashAt(a) <> 0 Then AddHash a
    Next i
End Sub

Sub InitHash
    Dim i As Long
    For i = 0 To HASH_SIZE - 1
        HashHead(i) = -1
        Hash4Head(i) = -1
        HashNHead(i) = -1
    Next i
    InitMethod8Hash
    For i = 0 To MEM_SIZE - 1
        HashNext(i) = -1
        Hash4Next(i) = -1
        HashNNext(i) = -1
        Decoded(i) = 0
        Hashed(i) = 0
        Hashed4(i) = 0
        HashedN(i) = 0
    Next i
End Sub

Sub AddHash (absAddr As Long)
    Dim h As Long
    If Hashed(absAddr) = 0 Then
        h = HashAt(absAddr)
        HashNext(absAddr) = HashHead(h)
        HashHead(h) = absAddr
        Hashed(absAddr) = 1
    End If
    If CanHash4At(absAddr) <> 0 Then
        If Hashed4(absAddr) = 0 Then
            h = Hash4At(absAddr)
            Hash4Next(absAddr) = Hash4Head(h)
            Hash4Head(h) = absAddr
            Hashed4(absAddr) = 1
        End If
    End If
    If CompressionMethod = 7 Then
        If CanHashNAt(absAddr) <> 0 Then
            If HashedN(absAddr) = 0 Then
                h = HashNAt(absAddr)
                HashNNext(absAddr) = HashNHead(h)
                HashNHead(h) = absAddr
                HashedN(absAddr) = 1
            End If
        End If
    End If
    If CompressionMethod = 8 Or CompressionMethod = 9 Then AddMethod8Hashes absAddr
End Sub

Function CanHashAt (absAddr As Long)
    If absAddr < 0 Or absAddr + 2 >= MEM_SIZE Then
        CanHashAt = 0
        Exit Function
    End If
    If (absAddr And &H1FFF) > &H1FFD Then
        CanHashAt = 0
        Exit Function
    End If
    If Used(absAddr) = 0 Or Used(absAddr + 1) = 0 Or Used(absAddr + 2) = 0 Then
        CanHashAt = 0
        Exit Function
    End If
    If Decoded(absAddr) = 0 Or Decoded(absAddr + 1) = 0 Or Decoded(absAddr + 2) = 0 Then
        CanHashAt = 0
        Exit Function
    End If
    CanHashAt = 1
End Function

Function CanHash4At (absAddr As Long)
    If absAddr < 0 Or absAddr + 3 >= MEM_SIZE Then
        CanHash4At = 0
        Exit Function
    End If
    If (absAddr And &H1FFF) > &H1FFC Then
        CanHash4At = 0
        Exit Function
    End If
    If Used(absAddr) = 0 Or Used(absAddr + 1) = 0 Or Used(absAddr + 2) = 0 Or Used(absAddr + 3) = 0 Then
        CanHash4At = 0
        Exit Function
    End If
    If Decoded(absAddr) = 0 Or Decoded(absAddr + 1) = 0 Or Decoded(absAddr + 2) = 0 Or Decoded(absAddr + 3) = 0 Then
        CanHash4At = 0
        Exit Function
    End If
    CanHash4At = 1
End Function

Function CanHashNAt (absAddr As Long)
    Dim i As Long
    If CompressionMethod <> 7 Then
        CanHashNAt = 0
        Exit Function
    End If
    If Method7HashLength < METHOD7_MIN_HASH_LENGTH Or Method7HashLength > METHOD7_MAX_HASH_LENGTH Then
        CanHashNAt = 0
        Exit Function
    End If
    If absAddr < 0 Or absAddr + Method7HashLength - 1 >= MEM_SIZE Then
        CanHashNAt = 0
        Exit Function
    End If
    If (absAddr And &H1FFF) > BLOCK_SIZE - Method7HashLength Then
        CanHashNAt = 0
        Exit Function
    End If
    For i = 0 To Method7HashLength - 1
        If Used(absAddr + i) = 0 Or Decoded(absAddr + i) = 0 Then
            CanHashNAt = 0
            Exit Function
        End If
    Next i
    CanHashNAt = 1
End Function

Function CanInputHashAt (absAddr As Long)
    If absAddr < 0 Or absAddr + 2 >= MEM_SIZE Then
        CanInputHashAt = 0
        Exit Function
    End If
    If (absAddr And &H1FFF) > &H1FFD Then
        CanInputHashAt = 0
        Exit Function
    End If
    If Used(absAddr) = 0 Or Used(absAddr + 1) = 0 Or Used(absAddr + 2) = 0 Then
        CanInputHashAt = 0
        Exit Function
    End If
    CanInputHashAt = 1
End Function

Function CanInputHash4At (absAddr As Long)
    If absAddr < 0 Or absAddr + 3 >= MEM_SIZE Then
        CanInputHash4At = 0
        Exit Function
    End If
    If (absAddr And &H1FFF) > &H1FFC Then
        CanInputHash4At = 0
        Exit Function
    End If
    If Used(absAddr) = 0 Or Used(absAddr + 1) = 0 Or Used(absAddr + 2) = 0 Or Used(absAddr + 3) = 0 Then
        CanInputHash4At = 0
        Exit Function
    End If
    CanInputHash4At = 1
End Function

Function CanInputHashNAt (absAddr As Long)
    Dim i As Long
    If CompressionMethod <> 7 Then
        CanInputHashNAt = 0
        Exit Function
    End If
    If Method7HashLength < METHOD7_MIN_HASH_LENGTH Or Method7HashLength > METHOD7_MAX_HASH_LENGTH Then
        CanInputHashNAt = 0
        Exit Function
    End If
    If absAddr < 0 Or absAddr + Method7HashLength - 1 >= MEM_SIZE Then
        CanInputHashNAt = 0
        Exit Function
    End If
    If (absAddr And &H1FFF) > BLOCK_SIZE - Method7HashLength Then
        CanInputHashNAt = 0
        Exit Function
    End If
    For i = 0 To Method7HashLength - 1
        If Used(absAddr + i) = 0 Then
            CanInputHashNAt = 0
            Exit Function
        End If
    Next i
    CanInputHashNAt = 1
End Function

Function HashAt (absAddr As Long)
    HashAt = ((CLng(Memory(absAddr)) * 257) Xor (CLng(Memory(absAddr + 1)) * 17) Xor CLng(Memory(absAddr + 2))) And (HASH_SIZE - 1)
End Function

Function Hash4At (absAddr As Long)
    Hash4At = ((CLng(Memory(absAddr)) * 4099) Xor (CLng(Memory(absAddr + 1)) * 257) Xor (CLng(Memory(absAddr + 2)) * 17) Xor CLng(Memory(absAddr + 3))) And (HASH_SIZE - 1)
End Function

Function HashNAt (absAddr As Long)
    Dim i As Long
    Dim h As Long
    h = 0
    For i = 0 To Method7HashLength - 1
        h = ((h * 257) Xor CLng(Memory(absAddr + i))) And (HASH_SIZE - 1)
    Next i
    HashNAt = h
End Function

Function EliasBits (value As Long)
    Dim bits As Long
    Dim tempValue As Long
    bits = 1
    tempValue = value
    Do While tempValue > 1
        tempValue = tempValue \ 2
        bits = bits + 2
    Loop
    EliasBits = bits
End Function

Function VerifyCompressedRange (absStart As Long, length As Long, compLen As Long)
    Dim outPos As Long
    Dim cmdBit As Long
    Dim copyType As Long
    Dim runLen As Long
    Dim i As Long
    Dim b As Long
    Dim sourceBlock As Long
    Dim sourceOffset As Long
    Dim sourceAbs As Long
    Dim lastSource As Long
    Dim sourceByteAbs As Long
    Dim value As Long

    ReDim VerifyOut(0 To length - 1) As _Unsigned _Byte
    ReadPos = 0
    ReadBitMask = 0
    ReadControlByte = 0
    outPos = 0
    lastSource = -1

    Do While outPos < length
        If ReadPos > compLen Then
            VerifyCompressedRange = 0
            Exit Function
        End If

        cmdBit = ReadCompBit
        If cmdBit = 0 Then
            runLen = ReadCompElias
            For i = 0 To runLen - 1
                If outPos >= length Then
                    VerifyCompressedRange = 0
                    Exit Function
                End If
                value = ReadCompByte
                VerifyOut(outPos) = value
                If value <> Memory(absStart + outPos) Then
                    VerifyCompressedRange = 0
                    Exit Function
                End If
                outPos = outPos + 1
            Next i
        Else
            copyType = ReadCompBit
            runLen = ReadCompElias
            If copyType <> 0 Then
                sourceBlock = ReadCompByte
                b = ReadCompByte
                sourceOffset = b * 256 + ReadCompByte
                sourceAbs = sourceBlock * BLOCK_SIZE + sourceOffset
                lastSource = sourceAbs
            Else
                If lastSource < 0 Then
                    VerifyCompressedRange = 0
                    Exit Function
                End If
                sourceAbs = lastSource
            End If

            For i = 0 To runLen - 1
                If outPos >= length Then
                    VerifyCompressedRange = 0
                    Exit Function
                End If
                sourceByteAbs = sourceAbs + i
                If sourceByteAbs >= absStart And sourceByteAbs < absStart + outPos Then
                    value = VerifyOut(sourceByteAbs - absStart)
                Else
                    If sourceByteAbs < 0 Or sourceByteAbs >= MEM_SIZE Then
                        VerifyCompressedRange = 0
                        Exit Function
                    End If
                    value = Memory(sourceByteAbs)
                End If
                VerifyOut(outPos) = value
                If value <> Memory(absStart + outPos) Then
                    VerifyCompressedRange = 0
                    Exit Function
                End If
                outPos = outPos + 1
            Next i
        End If
    Loop

    VerifyCompressedRange = 1
End Function

Function ReadCompBit
    If ReadBitMask = 0 Then
        ReadControlByte = CompOut(ReadPos)
        ReadPos = ReadPos + 1
        ReadBitMask = 128
    End If
    If (ReadControlByte And ReadBitMask) <> 0 Then
        ReadCompBit = 1
    Else
        ReadCompBit = 0
    End If
    ReadBitMask = ReadBitMask \ 2
End Function

Function ReadCompByte
    ReadCompByte = CompOut(ReadPos)
    ReadPos = ReadPos + 1
End Function

Function ReadCompElias
    Dim value As Long
    value = 1
    Do While ReadCompBit = 0
        value = value * 2
        If ReadCompBit <> 0 Then value = value + 1
    Loop
    ReadCompElias = value
End Function

Sub InitCompOut
    CompOutLen = 0
    CompBitMask = 0
    CompBitIndex = 0
End Sub

Sub EnsureCompCapacity (needBytes As Long)
    If needBytes > UBound(CompOut) Then
        ReDim _Preserve CompOut(0 To needBytes + 65535) As _Unsigned _Byte
    End If
End Sub

Sub CompWriteByte (value As Long)
    EnsureCompCapacity CompOutLen + 1
    CompOut(CompOutLen) = value And &HFF
    CompOutLen = CompOutLen + 1
End Sub

Sub CompWriteBit (value As Long)
    If CompBitMask = 0 Then
        CompBitMask = 128
        CompBitIndex = CompOutLen
        CompWriteByte 0
    End If
    If value <> 0 Then CompOut(CompBitIndex) = CompOut(CompBitIndex) Or CompBitMask
    CompBitMask = CompBitMask \ 2
End Sub

Sub CompWriteElias (value As Long)
    Dim bitMask As Long
    If value < 1 Then value = 1

    ' Same forward interlaced Elias shape used by zx0_Tool_07.BAS when
    ' backwards_mode=0 and invert_mode=0.
    If value = 1 Then
        CompWriteBit 1
        Exit Sub
    End If

    bitMask = 2
    Do While bitMask <= value
        bitMask = bitMask * 2
    Loop
    bitMask = bitMask \ 2

    CompWriteBit 0
    bitMask = bitMask \ 2
    Do While bitMask <> 0
        If (value And bitMask) <> 0 Then
            CompWriteBit 1
        Else
            CompWriteBit 0
        End If
        bitMask = bitMask \ 2
        If bitMask <> 0 Then CompWriteBit 0
    Loop
    CompWriteBit 1
End Sub

Sub FlushCompBits
    CompBitMask = 0
End Sub

Sub InitFileOut
    FileOutLen = 0
End Sub

Sub EnsureFileCapacity (needBytes As Long)
    If needBytes > UBound(FileOut) Then
        ReDim _Preserve FileOut(0 To needBytes + 65535) As _Unsigned _Byte
    End If
End Sub

Sub OutByte (value As Long)
    EnsureFileCapacity FileOutLen + 1
    FileOut(FileOutLen) = value And &HFF
    FileOutLen = FileOutLen + 1
End Sub

Sub OutWord (value As Long)
    OutByte (value \ 256) And &HFF
    OutByte value And &HFF
End Sub

Sub OutString (text As String)
    Dim i As Long
    For i = 1 To Len(text)
        OutByte Asc(Mid$(text, i, 1))
    Next i
End Sub

Sub PatchWord (patchPos As Long, value As Long)
    FileOut(patchPos) = (value \ 256) And &HFF
    FileOut(patchPos + 1) = value And &HFF
End Sub

Sub WriteFileOut (FileName As String)
    Dim f As Long
    If _FileExists(FileName) Then Kill FileName
    ReDim FinalOut(0 To FileOutLen - 1) As _Unsigned _Byte
    Dim i As Long
    For i = 0 To FileOutLen - 1
        FinalOut(i) = FileOut(i)
    Next i
    f = FreeFile
    Open FileName For Binary As #f
    Put #f, , FinalOut()
    Close #f
End Sub

Sub InitDiskOut
    DiskOutLen = 0
End Sub

Sub EnsureDiskCapacity (needBytes As Long)
    If needBytes > UBound(DiskOut) Then
        ReDim _Preserve DiskOut(0 To needBytes + 65535) As _Unsigned _Byte
    End If
End Sub

Sub DiskAddByte (value As Long)
    EnsureDiskCapacity DiskOutLen + 1
    DiskOut(DiskOutLen) = value And &HFF
    DiskOutLen = DiskOutLen + 1
End Sub

Sub DiskAddWord (value As Long)
    DiskAddByte (value \ 256) And &HFF
    DiskAddByte value And &HFF
End Sub

Sub DiskStartLoadRecord (loadAddr As Long, byteCount As Long)
    DiskAddByte 0
    DiskAddWord byteCount
    DiskAddWord loadAddr
End Sub

Sub DiskAddOneByteLoadRecord (loadAddr As Long, value As Long)
    DiskStartLoadRecord loadAddr, 1
    DiskAddByte value
End Sub

Sub DiskAddFileOutLoadRecord (loadAddr As Long, startPos As Long, byteCount As Long)
    Dim i As Long
    DiskStartLoadRecord loadAddr, byteCount
    For i = 0 To byteCount - 1
        DiskAddByte FileOut(startPos + i)
    Next i
End Sub

Sub DiskAddLoadScreenRecord (screenIndex As Long)
    Dim i As Long
    DiskStartLoadRecord TEXT_SCREEN_ADDR, LOAD_SCREEN_BYTES
    For i = 0 To LOAD_SCREEN_BYTES - 1
        DiskAddByte LoadScreenBlock(screenIndex, i)
    Next i
End Sub

Sub ResolveLoadScreenBlocks (sourceBlockCount As Long)
    Dim percent As Long
    Dim blockIndex As Long
    Dim offset As Long

    For blockIndex = 0 To MAX_SOURCE_BLOCK_SCREENS - 1
        ShowLoadScreenBlock(blockIndex) = 0
        For offset = 0 To LOAD_SCREEN_BYTES - 1
            LoadScreenBlock(blockIndex, offset) = &H20
        Next offset
    Next blockIndex

    If sourceBlockCount <= 0 Then Exit Sub
    If sourceBlockCount > MAX_SOURCE_BLOCK_SCREENS Then
        Print "Internal error: source block count exceeds loading-screen table."
        System
    End If

    For percent = 0 To MAX_LOAD_SCREEN_PERCENTS - 1
        If ShowLoadScreenPercent(percent) <> 0 Then
            blockIndex = (percent * sourceBlockCount) \ 100
            If blockIndex >= sourceBlockCount Then blockIndex = sourceBlockCount - 1
            ShowLoadScreenBlock(blockIndex) = 1
            For offset = 0 To LOAD_SCREEN_BYTES - 1
                LoadScreenBlock(blockIndex, offset) = LoadScreenPercent(percent, offset)
            Next offset
            If Verbose > 0 Then Print "Loading-screen percent"; percent; "mapped to source block"; blockIndex
        End If
    Next percent
End Sub

Sub DiskAddLoadProgressRecord (loadedBlocks As Long, totalBlocks As Long)
    Dim barSize As Long
    Dim fullBlocks As Long
    Dim loadPercent As Long
    Dim x As Long
    Dim text As String
    Dim percent As String
    Dim lineText As String

    If totalBlocks <= 0 Then Exit Sub

    barSize = (loadedBlocks * LOAD_PROGRESS_HALF_STEPS) \ totalBlocks
    If barSize < 0 Then barSize = 0
    If barSize > LOAD_PROGRESS_HALF_STEPS Then barSize = LOAD_PROGRESS_HALF_STEPS

    loadPercent = (loadedBlocks * 100) \ totalBlocks
    If loadPercent < 0 Then loadPercent = 0
    If loadPercent > 100 Then loadPercent = 100

    ' CoCo text screen codes: A=$01, L=$0C, O=$0F, [=$1B, ]=$1D.
    text = Chr$(&H0C) + Chr$(&H0F) + Chr$(&H01) + Chr$(&H04) + Chr$(&H09) + Chr$(&H0E) + Chr$(&H07) + Chr$(&H1B)

    fullBlocks = barSize \ 2
    If fullBlocks > 0 Then text = text + String$(fullBlocks, Chr$(&HFF))
    If (barSize And 1) <> 0 Then text = text + Chr$(&HFA)

    percent = Chr$(&H1D) + Right$("  " + LTrim$(Str$(loadPercent)), 3) + "%"
    lineText = Left$(text + String$(TEXT_LINE_BYTES, " "), TEXT_LINE_BYTES - Len(percent)) + percent

    DiskStartLoadRecord LOAD_PROGRESS_LINE_ADDR, TEXT_LINE_BYTES
    For x = 1 To TEXT_LINE_BYTES
        DiskAddByte Asc(Mid$(lineText, x, 1))
    Next x
End Sub

Sub DiskAddExecRecord (execAddr As Long)
    DiskAddByte &HFF
    DiskAddWord 0
    DiskAddWord execAddr
End Sub

Sub WriteDiskOut (FileName As String)
    Dim f As Long
    Dim i As Long
    If _FileExists(FileName) Then Kill FileName
    ReDim FinalDiskOut(0 To DiskOutLen - 1) As _Unsigned _Byte
    For i = 0 To DiskOutLen - 1
        FinalDiskOut(i) = DiskOut(i)
    Next i
    f = FreeFile
    Open FileName For Binary As #f
    Put #f, , FinalDiskOut()
    Close #f
End Sub

Sub WriteReport (ReportName As String, PacketFileName As String)
    Dim f As Long
    Dim block As Long
    Dim offset As Long
    Dim usedCount As Long
    Dim i As Long
    Dim packet As Long
    Dim finalDestinationBytes As Long
    Dim sourceSavings As Long
    Dim destinationSavings As Long

    If _FileExists(ReportName) Then Kill ReportName
    f = FreeFile
    Open ReportName For Output As #f

    finalDestinationBytes = TotalLiteralBytes + TotalCopyBytes
    sourceSavings = TotalSourceFileBytes - FileOutLen
    destinationSavings = finalDestinationBytes - FileOutLen

    Print #f, "CC3_Comp v"; VERSION$; " report"
    Print #f, "Packet file: "; PacketFileName
    Print #f, "Original source size:"; TotalSourceFileBytes; " bytes"
    Print #f, "Final destination size:"; finalDestinationBytes; " bytes"
    Print #f, "Compressed packet stream size:"; FileOutLen; " bytes"
    Print #f, "Savings vs original source:"; sourceSavings; " bytes ("; FormatPercent$(sourceSavings, TotalSourceFileBytes); ")"
    Print #f, "Savings vs final destination:"; destinationSavings; " bytes ("; FormatPercent$(destinationSavings, finalDestinationBytes); ")"
    Print #f, "EXEC address: $"; Hex4$(ExecuteAddr)
    Print #f, "Final handoff stub: $"; Hex4$(FinalJumpAddr)
    Print #f, "Max uncompressed packet bytes:"; MaxPacketUncomp
    Print #f, "Max hash-chain checks:"; MaxChainChecks
    Print #f, "Compression method: "; MethodName$
    If AutoMode <> AUTO_NONE And AutoResultCount > 0 Then
        Print #f, "Auto compression mode: "; AutoModeName$
        If ZeroFillEnabled <> 0 Then
            Print #f, "Auto mode used -Z$"; Hex2$(ZeroFillValue); " for every candidate."
        Else
            Print #f, "Auto mode tested methods with zero-fill off."
        End If
        Print #f, "Auto candidate results:"
        For i = 0 To AutoResultCount - 1
            If i = AutoResultWinner Then
                Print #f, "  * "; AutoResultName(i); " "; AutoResultBytes(i); " bytes "; FormatSeconds$(AutoResultSeconds(i)); "s"
            Else
                Print #f, "    "; AutoResultName(i); " "; AutoResultBytes(i); " bytes "; FormatSeconds$(AutoResultSeconds(i)); "s"
            End If
        Next i
    End If
    If LazyMatching <> 0 Then
        Print #f, "One-byte lazy matching: on"
    Else
        Print #f, "One-byte lazy matching: off"
    End If
    If ZeroFillEnabled <> 0 Then
        Print #f, "Zero-fill internal gaps in used MMU blocks: on, value $"; Hex2$(ZeroFillValue); ", added "; ZeroFillBytes; " bytes"
    Else
        Print #f, "Zero-fill internal gaps in used MMU blocks: off"
    End If
    Select Case CompressionMethod
        Case 2
            Print #f, "Selected method detail: range split original "; Method2OriginalRangeCount; ", split "; Method2SplitRangeCount; ", extra "; Method2ExtraRangeCount
        Case 3
            Print #f, "Selected method detail: bounded optimal/lazy parse with conservative greedy fallback"
        Case 4
            Print #f, "Selected method detail: repeated-fill runs "; Method4FillCommands; " runs,"; Method4FillBytes; " bytes"
        Case 5
            Print #f, "Selected method detail: repeated-pattern runs "; Method5PatternCommands; " runs,"; Method5PatternBytes; " bytes"
        Case 6
            Print #f, "Selected method detail: wider match tests, 3-byte "; Method6Hash3Tests; ", 4-byte "; Method6Hash4Tests; ", old samples "; Method6OldSampleTests; ", duplicate skips "; Method6DuplicateSkips
        Case 7
            Print #f, "Selected method detail: long hash length "; Method7HashLength; " bytes, long-hash tests "; Method7HashTests
        Case 8
            Print #f, "Selected method detail: descending long-hash search "; Method7HashLength; " bytes down to 4, long-hash tests "; Method8HashTests
        Case 9
            Print #f, "Selected method detail: exhaustive ascending long-hash search 4 bytes up to "; Method7HashLength; ", long-hash tests "; Method8HashTests
    End Select
    If CompressionMethod < 1 Then
        Print #f, "Range ordering: off"
    ElseIf RangeOrderSkipped <> 0 Then
        Print #f, "Range ordering: skipped, too many packet ranges"
    ElseIf RangeOrderNormalCount > 2 Then
        Print #f, "Range ordering: on, normal ranges "; RangeOrderNormalCount; ", moved "; RangeOrderMovedCount
    Else
        Print #f, "Range ordering: not needed"
    End If
    Print #f, "Disk BASIC LOADM source block: $"; Hex2$(SourceWindowBlock)
    If SourceWindowBorrowed <> 0 Then Print #f, "  borrowed from user data and delayed until final decode"
    Print #f, "Decoder source block: $"; Hex2$(DecodeSourceBlock)
    Print #f,

    Print #f, "Final task-0 MMU map ($FFA0-$FFA7):";
    For i = 0 To 7
        Print #f, " $"; Hex2$(PageBlock0(i));
    Next i
    Print #f,

    Print #f, "Final task-1 MMU map ($FFA8-$FFAF):";
    For i = 0 To 7
        Print #f, " $"; Hex2$(PageBlock1(i));
    Next i
    Print #f,
    Print #f,

    Print #f, "Disk BASIC shadow plan:"
    If ShadowCount = 0 Then
        Print #f, "  none"
    Else
        For i = 0 To ShadowCount - 1
            Print #f, "  original $"; Hex2$(Shadows(i).originalBlock); " -> shadow $"; Hex2$(Shadows(i).shadowBlock)
        Next i
    End If
    Print #f,

    Print #f, "Block map:"
    Print #f, "  .... unused, USER touched by program, LOAD old loader, SHAD Disk BASIC shadow, SRC source window"
    For block = 0 To BLOCK_COUNT - 1 Step 8
        Print #f, "  $"; Hex2$(block); " ";
        For i = 0 To 7
            Select Case BlockMap(block + i)
                Case BLOCK_UNUSED
                    Print #f, ".... ";
                Case BLOCK_USER
                    Print #f, "USER ";
                Case BLOCK_LOADER
                    Print #f, "LOAD ";
                Case BLOCK_SHADOW
                    Print #f, "SHAD ";
                Case BLOCK_SOURCE
                    Print #f, "SRC  ";
                Case Else
                    Print #f, "???? ";
            End Select
        Next i
        Print #f,
    Next block
    Print #f,

    Print #f, "Used bytes per physical MMU block:"
    For block = 0 To BLOCK_COUNT - 1
        usedCount = 0
        For offset = 0 To BLOCK_SIZE - 1
            If Used(block * BLOCK_SIZE + offset) <> 0 Then usedCount = usedCount + 1
        Next offset
        If usedCount <> 0 Then
            Print #f, "  block $"; Hex2$(block); " used $"; Hex4$(usedCount); " bytes"
        End If
    Next block
    Print #f,

    Print #f, "Output packet ranges:"
    For packet = 0 To RangeCount - 1
        Print #f, "  "; packet + 1; ": block $"; Hex2$(Ranges(packet).block); " offset $"; Hex4$(Ranges(packet).offset); " length $"; Hex4$(Ranges(packet).length)
    Next packet
    Print #f,

    Print #f, "Streaming disk files:"
    If StreamChunkCount = 0 Then
        Print #f, "  none"
    Else
        For i = 0 To StreamChunkCount - 1
            Print #f, "  DISK"; LTrim$(Str$(StreamChunkDisk(i))); ".DSK : "; ChunkFileName$(i); "  flags $"; Hex2$(StreamChunkFlags(i))
        Next i
    End If
    Print #f,

    Print #f, "Command stream format for each packet:"
    Print #f, "  packet header: destination block, destination offset, output length, compressed length"
    Print #f, "  bit 0: literal run, Elias length, raw bytes"
    Print #f, "  bit 1 then bit 1: new copy source, Elias length, source block, source offset word"
    Print #f, "  bit 1 then bit 0: repeat previous copy source, Elias length"
    Print #f, "  packet ends after output length bytes have been produced"
    Print #f,

    Print #f, "Compression totals:"
    Print #f, "  literal bytes:"; TotalLiteralBytes
    Print #f, "  copy bytes:"; TotalCopyBytes
    Print #f, "  literal commands:"; TotalLiteralCommands
    Print #f, "  copy commands:"; TotalCopyCommands
    Print #f, "  packet file bytes:"; FileOutLen

    Close #f
End Sub

Function Hex2$ (value As Long)
    Hex2$ = Right$("00" + Hex$(value And &HFF), 2)
End Function

Function Hex4$ (value As Long)
    Hex4$ = Right$("0000" + Hex$(value And &HFFFF), 4)
End Function
