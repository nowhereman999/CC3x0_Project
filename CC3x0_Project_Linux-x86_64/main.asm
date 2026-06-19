        ORG     $0600

Start:
        ORCC    #$50
        LDX     #$0400
        LDY     #$0200
        LDA     #$01

ClearScreen:
        STA     ,X+
        LEAY    -1,Y
        BNE     ClearScreen

Hold:
        BRA     Hold

        END     Start
