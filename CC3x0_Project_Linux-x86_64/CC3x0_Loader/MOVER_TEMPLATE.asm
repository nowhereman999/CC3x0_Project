* CC3_Mover.asm
*
* Helper for the BASIC-driven streaming loader.
*
* BASIC loads this at $1300.  The compressor patches the bytes at $1300-$130B in
* MOVER_TEMPLATE.BIN and writes the final MOVER.BIN for the specific program
* being compressed.
*
* It has two entry points:
*
*   $130E  MoverMapSourceEntry
*          Maps a spare source block into $2000-$3FFF, moves the stack from
*          $7Fxx down to $1Fxx, switches the CoCo 3 back to ROM mode, and
*          returns to BASIC.  BASIC then LOADMs COMP####.BIN chunks into that
*          scratch block, and the decoder can freely remap $6000-$7FFF through
*          $FFA3 without hiding the stack.
*
*   $1311  MoverFinalEntry
*          Runs only for the final chunk that writes physical block $38.  It
*          shadows $38, keeps the stack at $1F00, then jumps directly to the
*          decoder at $0F00.  It must not return to BASIC after $FFA0 is
*          remapped because low RAM would no longer contain the loader.
*
* Final mover work:
*   - disables IRQ/FIRQ while MMU mappings and the stack are being moved
*   - copies protected Disk BASIC physical blocks to spare physical blocks
*   - maps those spare blocks into the active task-0 logical banks
*   - restores the compressed-source window at $FFA1
*   - moves the stack if it was not already moved by $130E
*   - jumps to the streaming decoder

MMU0_BASE               EQU     $FFA0
SOURCE_MMU              EQU     $FFA1
DEST_MMU                EQU     $FFA2
ROM_MODE_ENABLE         EQU     $FFDE
RAM_MODE_ENABLE         EQU     $FFDF
SOURCE_WINDOW           EQU     $2000
DEST_WINDOW             EQU     $4000
STACK_OLD_PAGE          EQU     $7F00
STACK_NEW_PAGE          EQU     $1F00
STACK_MOVE_DELTA        EQU     STACK_OLD_PAGE-STACK_NEW_PAGE
DECODER_ENTRY           EQU     $0F00

    ORG     $1300

* Patched by CC3_Comp.bas after it has analyzed the user's LOADM file.
MoverShadowCount        FCB     0       
MoverLoadBlock          FCB     0       
MoverDecodeBlock        FCB     0       
MoverShadowPairs        FCB     0,0,0,0,0,0,0,0,0,0

MoverPairCounter        FCB     0

MoverMapSourceEntry:
      JMP   MapSourceOnly

MoverFinalEntry:
      JMP   FinalMover

MapSourceOnly:
      PSHS  CC,D,X,U
      ORCC  #$50
      CLRA
      STA   ROM_MODE_ENABLE
      LDA   MoverLoadBlock
      STA   SOURCE_MMU
      JSR   MoveStackIfNeeded
      PULS  CC,D,X,U,PC

FinalMover:
      ORCC  #$50              ; Stop interrupts
      CLRA
      STA   RAM_MODE_ENABLE    ; Shadow copies may target physical $3C-$3F RAM.

* Copy each original protected physical block to its spare shadow block.
    LDA     MoverShadowCount
    STA     MoverPairCounter
    BEQ     MapSourceWindow

    LDX     #MoverShadowPairs
CopyShadowLoop:
    LDA     ,X+
    STA     SOURCE_MMU
    LDA     ,X+
    STA     DEST_MMU
    PSHS    X
    JSR     Copy8K
    PULS    X
    DEC     MoverPairCounter
    BNE     CopyShadowLoop

* Replace the active logical banks with the spare shadows.  The $38 shadow is
* first in the table, so when $FFA0 changes, this same code continues executing
* from the copy that was just made.
    LDA     MoverShadowCount
    STA     MoverPairCounter
    LDX     #MoverShadowPairs
MapShadowLoop:
    LDA     ,X+
    TFR     A,B
    SUBB    #$38
    LDA     ,X+
    PSHS    X
    LDX     #MMU0_BASE
    ABX
    STA     ,X
    PULS    X
    DEC     MoverPairCounter
    BNE     MapShadowLoop

MapSourceWindow:
      LDA   MoverLoadBlock
      STA   SOURCE_MMU

      JSR   MoveStackIfNeeded
      JMP   DECODER_ENTRY

MoveStackIfNeeded:
* Keep the active stack out of $6000-$7FFF because the decoder remaps that
* logical bank through $FFA3 for arbitrary physical copy-source blocks.
      TFR   S,D
      CMPA  #STACK_OLD_PAGE/256
      BNE   StackAlreadyMoved

* The BASIC EXEC return address and any saved registers are copied too, so
* after LEAS adjusts S by the same offset, execution can continue normally.
      LDX   #STACK_OLD_PAGE
      LDU   #STACK_NEW_PAGE
!     LDD   ,X++
      STD   ,U++
      CMPX  #$8000
      BNE   <
      LEAS  STACK_NEW_PAGE-STACK_OLD_PAGE,S     ; Use new stack position
StackAlreadyMoved:
      RTS

Copy8K:
    LDX     #SOURCE_WINDOW
    LDU     #DEST_WINDOW
    LDY     #$2000
Copy8KLoop:
    LDA     ,X+
    STA     ,U+
    LEAY    -1,Y
    BNE     Copy8KLoop
    RTS

    END     MoverMapSourceEntry
