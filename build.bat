@echo off

set TargetName=poe

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

@REM Compiler Options
set CompilerFiles=poe.cpp SplitRecv.cpp
set CompilerOptions=/LD /W3 /EHsc /Fe:%TargetName%
@REM Linker Options
set LinkerOptions=
set LinkerLibrary="kernel32.lib" "user32.lib" "	ws2_32.lib"

cl %CompilerFiles% %CompilerOptions% /link %LinkerOptions% %LinkerLibrary% 
cl inject.c


del *.obj
