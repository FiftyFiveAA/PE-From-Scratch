bits 64

; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#:~:text=The%20PE%20file%20header%20consists,followed%20immediately%20by%20section%20headers.
; ./nasm -O0 -f bin -o fun.exe fun.asm

; This exe has 3 sections (.text, .data, .idata)
; file offsets(.text=0x400, .data=0x2400, .idata=0x3400)
; memory offsets(.text = 0x1000, .data=0x3000, .idata=0x4000)

; CONSTANTS
TEXT_START_RVA EQU 0x1000  ; offset IN MEMORY from beginning of image
DATA_START_RVA EQU 0x3000  ; offset IN MEMORY from beginning of image
IDATA_START_RVA EQU 0x4000  ; offset IN MEMORY from beginning of image

TEXT_SIZE_RVA EQU 0x2000 ; start of data - start of text
DATA_SIZE_RVA EQU 0x1000  ; start of idata - start of data
IDATA_SIZE_RVA EQU 0x1000

TEXT_START_ENTRYPOINT_RVA EQU TEXT_START_RVA + ENTRYPOINT - TEXT_START

SIZE_OF_IMAGE EQU IDATA_START_RVA + IDATA_SIZE_RVA; how much memory will need to be allocated? add last section RVA and last section size. In this case it's IDATA

IMAGE_BASE EQU 0x0000000000400000

FILE_START:
; MS-DOS MZ Header (128 bytes) 0x00 - 0x7f
    dw 'MZ'
    db 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      ; e_lfanew is in there, at offset 0x3c and has a value of 0x80 which is start of PE Header

; PE FILE HEADER
    db 'PE', 0, 0     ; mMagic
    dw 0x8664         ; mMachine (machine type) 64 bit 0x8664,   32 bit 0x14c (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)
    dw 0x0003         ; mNumberOfSections
    dd 0x5fd2de05     ; mTimeDateStamp (https://dqydj.com/date-to-unix-time-converter/)
    dd 0x00000000     ; mPointerToSymbolTable
    dd 0x00000000     ; mNumberOfSymbols
    dw PE_OPTIONAL_HEADER_END - PE_OPTIONAL_HEADER_START ; mSizeOfOptionalHeader
    dw 0x0202         ; mCharacteristics (image valid/debugging info removed)(systemfile/dll)(https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)

; PE OPTIONAL HEADER
PE_OPTIONAL_HEADER_START:
    dw 0x020b                 ; uint16_t mMagic; // 0x010b = PE32 (32 bit), 0x020b = PE32+ (64 bit)
    db 0x02                   ;	uint8_t  mMajorLinkerVersion;
    db 0x20                   ;	uint8_t  mMinorLinkerVersion;
    dd TEXT_SIZE_RVA          ;	uint32_t mSizeOfCode;
    dd DATA_SIZE_RVA          ;	uint32_t mSizeOfInitializedData;
    dd 0x00000000             ;	uint32_t mSizeOfUninitializedData;
    dd TEXT_START_ENTRYPOINT_RVA    ;	uint32_t mAddressOfEntryPoint;
    dd TEXT_START_RVA         ;	uint32_t mBaseOfCode;
    ;absent in 64 bit         ;	uint32_t mBaseOfData;
    dq IMAGE_BASE             ;	uint64_t mImageBase;
    dd 0x00001000             ;	uint32_t mSectionAlignment; // 4096 bytes aka default page size
    dd 0x00000200             ;	uint32_t mFileAlignment;  // 512 bytes aka default
    dw 0x0004                 ;	uint16_t mMajorOperatingSystemVersion;
    dw 0x0000                 ;	uint16_t mMinorOperatingSystemVersion;
    dw 0x0000                 ;	uint16_t mMajorImageVersion;
    dw 0x0000                 ;	uint16_t mMinorImageVersion;
    dw 0x0005                 ;	uint16_t mMajorSubsystemVersion;
    dw 0x0002                 ;	uint16_t mMinorSubsystemVersion;
    dd 0x00000000             ;	uint32_t mWin32VersionValue;  // reserved, must be zero
    dd SIZE_OF_IMAGE          ;	uint32_t mSizeOfImage; needs to be section aligned
    dd TEXT_START             ;	uint32_t mSizeOfHeaders;
    dd 0x0000791b             ;	uint32_t mCheckSum; IMPLEMENT LATER, I just use PEStudio to tell me the correct checksum
    dw 0x0003                 ;	uint16_t mSubsystem; (3=console, 2=gui)(https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem)
    dw 0x0000                 ;	uint16_t mDllCharacteristics;  this is where you turn on aslr and stuff (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics)
    dq 0x0000000000200000     ;	uint64_t mSizeOfStackReserve;  max size of stack
    dq 0x0000000000001000     ;	uint64_t mSizeOfStackCommit;  size of stack to commit
    dq 0x0000000000100000     ;	uint64_t mSizeOfHeapReserve;
    dq 0x0000000000001000     ;	uint64_t mSizeOfHeapCommit;
    dd 0x00000000             ;	uint32_t mLoaderFlags;
    dd (DATA_DIRECTORY_END - DATA_DIRECTORY_START)/8  ;	uint32_t mNumberOfRvaAndSizes;

    ; OPTIONAL HEADER DATA DIRECTORIES
    DATA_DIRECTORY_START:
        ; EXPORT TABLE  // .edata
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; IMPORT TABLE  // .idata
              dd IDATA_START_RVA                         ; VIRTUAL ADDR
              dd IMPORT_TABLE_END - IMPORT_TABLE_START   ; SIZE
        ; RESOURCE TABLE  // .rsc
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; EXCEPTION TABLE  // .pdata
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; CERTIFICATE/SECURITY TABLE
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; BASE RELOCATION TABLE  // .reloc
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; DEBUG  // .debug
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; ARCHITECTURE
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; GLOBAL PTR
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; TLS TABLE  // .tls
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; LOAD CONFIG TABLE
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; BOUND IMPORT
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; IMPORT ADDRESS TABLE (IAT)
              dd IDATA_START_RVA + IMPORT_LOOKUP_TABLE_START - IDATA_START   ; VIRTUAL ADDR
              dd IMPORT_LOOKUP_TABLE_END - IMPORT_LOOKUP_TABLE_START         ; SIZE
        ; DELAY IMPORT DESCRIPTOR
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; CLR RUNTIME HEADER
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
        ; RESERVED, MUST BE ZERO
              dd 0x00000000   ; VIRTUAL ADDR
              dd 0x00000000   ; SIZE
    DATA_DIRECTORY_END:
PE_OPTIONAL_HEADER_END:

; SECTION HEADERS    (each entry is 40 bytes)
    TEXT_HEADER_START:
        dq '.text'                  ; dq Name  // section name
        dd TEXT_SIZE_RVA            ; dd VirtualSize  // size of section in memory
        dd TEXT_START_RVA           ; dd VirtualAddress  // start of section addr in memory
        dd TEXT_END - TEXT_START    ; dd SizeOfRawData  // size of section in file
        dd TEXT_START               ; dd PointerToRawData  // size of section in file
        dd 0x00000000               ; dd PointerToRelocations
        dd 0x00000000               ; dd PointerToLineNumbers
        dw 0x0000                   ; dw NumberOfRelocations
        dw 0x0000                   ; dw NumberOfLineNumbers
        dd 0x0000000060500060       ; dd Characteristics  (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)
    TEXT_HEADER_END:

    DATA_HEADER_START:
        dq '.data'                  ; dq Name  // section name
        dd DATA_SIZE_RVA            ; dd VirtualSize  // size of section in memory
        dd DATA_START_RVA           ; dd VirtualAddress  // start of section addr in memory
        dd DATA_END - DATA_START    ; dd SizeOfRawData  // size of section in file
        dd DATA_START               ; dd PointerToRawData  // size of section in file
        dd 0x00000000               ; dd PointerToRelocations
        dd 0x00000000               ; dd PointerToLineNumbers
        dw 0x0000                   ; dw NumberOfRelocations
        dw 0x0000                   ; dw NumberOfLineNumbers
        dd 0x00000000c0600040       ; dd Characteristics  (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)
    DATA_HEADER_END:

    IDATA_HEADER_START:
        dq '.idata'                 ; dq Name  // section name
        dd IDATA_SIZE_RVA           ; dd VirtualSize  // size of section in memory
        dd IDATA_START_RVA          ; dd VirtualAddress  // start of section addr in memory
        dd IDATA_END - IDATA_START  ; dd SizeOfRawData  // size of section in file
        dd IDATA_START              ; dd PointerToRawData  // size of section in file
        dd 0x00000000               ; dd PointerToRelocations
        dd 0x00000000               ; dd PointerToLineNumbers
        dw 0x0000                   ; dw NumberOfRelocations
        dw 0x0000                   ; dw NumberOfLineNumbers
        dd 0x00000000c0300040       ; dd Characteristics  (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)
    IDATA_HEADER_END:

; SECTIONS
    ; need each section to fileAlign which is 0x200 as defined earlier
    times 0x400-($-FILE_START) db 0x00

    TEXT_START:  ; starts at offset 0x400 in file
        ENTRYPOINT:
            sub rsp, 8  ; align stack to 16 bytes

            xor ecx, ecx
            mov rdx, DATA_START_RVA + MessageBoxText - DATA_START + IMAGE_BASE
            mov r8, DATA_START_RVA + MessageBoxCaption - DATA_START + IMAGE_BASE
            mov r9d, 0x104
            mov rax, TEXT_START_RVA + USER32_MESSAGEBOXA - TEXT_START + IMAGE_BASE
            call [rax]

            mov rcx, -11
            mov rax, TEXT_START_RVA + KERNEL32_GETSTDHANDLE - TEXT_START + IMAGE_BASE
            call [rax]

            jmp $
    TEXT_END:

    ; need each section to fileAlign which is 0x200 as defined earlier
    times 0x2400-($-FILE_START) db 0x00

    DATA_START:  ; starts at offset 0x2400 in file
        NAME_KERNEL32_DLL: db 'kernel32.dll', 0
        NAME_USER32_DLL: db 'user32.dll', 0
        MessageBoxText: db "hey how are you?", 0
        MessageBoxCaption: db "YOYO", 0
        CmdLineOutput: db "well this is fun :)", 0
          CmdLineOutputLength EQU $-CmdLineOutput
    DATA_END:

    ; need each section to fileAlign which is 0x200 as defined earlier
    times 0x3400-($-FILE_START) db 0x00

    IDATA_START:  ; starts at offset 0x3400 in file
        IMPORT_TABLE:
            IMPORT_TABLE_START:  ; array, 20 bytes per entry, one for each DLL
                ; import kernel32.dll
                dd IDATA_START_RVA + KERNEL32_LOOKUP_TABLE_START - IDATA_START    ; dd Import Lookup Table RVA  // table contains name/ordinal for each import
                dd 0x00000000                   ; dd Time/Date stamp
                dd 0x00000000                   ; dd Forwarder Chain
                dd DATA_START_RVA + NAME_KERNEL32_DLL - DATA_START              ; Name RVA. pointer to string of DLL name
                dd IDATA_START_RVA + KERNEL32_LOOKUP_TABLE_START - IDATA_START             ; Import Address Table RVA (Thunk Table)

                ; import user32.dll
                dd IDATA_START_RVA + USER32_LOOKUP_TABLE_START - IDATA_START    ; dd Import Lookup Table RVA  // table contains name/ordinal for each import
                dd 0x00000000                   ; dd Time/Date stamp
                dd 0x00000000                   ; dd Forwarder Chain
                dd DATA_START_RVA + NAME_USER32_DLL - DATA_START              ; Name RVA. pointer to string of DLL name
                dd IDATA_START_RVA + USER32_LOOKUP_TABLE_START - IDATA_START             ; Import Address Table RVA (Thunk Table)

                ; last entry must be null
                dd 0x00000000
                dd 0x00000000
                dd 0x00000000
                dd 0x00000000
                dd 0x00000000
            IMPORT_TABLE_END:

            IMPORT_LOOKUP_TABLE_START:  ; array, 64 bit numbers
                ; Import address table. Modified by the PE loader before jumping to _entry.
                ; These entries will eventually contain pointers to the functions in memory.
                ; 0x8000000000000000  import by ordinal, aka most significant bit set to 1 if ordinal
                ; 0x0000000000000000  import by name, aka most significant bit set to 0 if name
                ; 0x800000000000ffff  ordinal is 16 bit number, so at most 0xffff
                ; 0x000000007fffffff  31 bit RVA of hint/name table entry, so at most 0x7fffffff
                ; last entry must be null

                KERNEL32_LOOKUP_TABLE_START:
                    ; kernel32.dll GetStdHandle
                    KERNEL32_GETSTDHANDLE: dq 0x0000000000000000 + IDATA_START_RVA + HINT_NAME_TABLE_KERNEL32_GETSTDHANDLE - IDATA_START
                    KERNEL32_WRITEFILE: dq 0x0000000000000000 + IDATA_START_RVA + HINT_NAME_TABLE_KERNEL32_WRITEFILE - IDATA_START
                    dq 0x0000000000000000  ; make last entry null

                USER32_LOOKUP_TABLE_START:
                    ; user32.dll MessageBoxA
                    USER32_MESSAGEBOXA:  dq 0x0000000000000000 + IDATA_START_RVA + HINT_NAME_TABLE_USER32_MESSAGEBOXA - IDATA_START
                    dq 0x0000000000000000  ; make last entry null
            IMPORT_LOOKUP_TABLE_END:

            HINT_NAME_TABLE_START:
                ; dw Hint  // index into export name pointer table, if no match loader searches in DLL's export name pointer table
                ; Name     // null terminated ascii string, aka function to import
                ; db Pad   // need to align next entry on an even boundary, so this may not be necessary

                ; kernel32.dll GetStdHandle()
                HINT_NAME_TABLE_KERNEL32_GETSTDHANDLE:
                dw 0x0000  ; Hint
                db 'GetStdHandle', 0  ; Name
                db 0x00  ; Pad, since ('GetStdHandle', 0) is an odd number aka 13 bytes

                ; kernel32.dll WriteFile()
                HINT_NAME_TABLE_KERNEL32_WRITEFILE:
                dw 0x0000  ; Hint
                db 'WriteFile', 0  ; Name
                ;db 0x00  ; DON'T Pad, since ('WriteFile', 0) is an even number aka 10 bytes

                HINT_NAME_TABLE_USER32_MESSAGEBOXA:
                dw 0x0000  ; Hint
                db 'MessageBoxA', 0  ; Name
                ;db 0x00  ; DON'T Pad, since ('MessageBoxA', 0) is an even number aka 12 bytes

            HINT_NAME_TABLE_END:
    IDATA_END:

    times 0x4400-($-FILE_START) db 0x00

FILE_END:
