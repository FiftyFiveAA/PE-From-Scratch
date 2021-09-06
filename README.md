# PE-From-Scratch
Creates a 64 bit Portable Executable using assembly (NASM) from scratch

### Usage

##### Create the exe using NASM

```
nasm -O0 -f bin -o pe64bit.exe pe64bit.asm
```

### About
pe64bit.asm creates a 64 bit Windows Portable Executable from scratch. To demonstrate how to import DLLs/functions I went ahead and added some optional imports:

* kernel32.dll
  - GetStdHandle
  - WriteFile  // is not used, just to show how to import multiple functions from one DLL
* user32.dll
  - MessageBoxA

I created this because I:
  1. Wanted to learn the inner workings of 64 bit portable executables
  2. Was unable to find a 64 bit PE from scratch anywhere
  3. Wanted an easy way to write custom assembly and include it in a PE
