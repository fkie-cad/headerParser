@echo off

set target=headerParser
set bitness=64
set mode=Release
set buildTools="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\"
set cmake_path="C:\Program Files\cmake\bin\cmake.exe"
set cmake=cmake

set prog_name=%~n0
set user_dir="%~dp0"
set verbose=1
set mt=no
set pdb=0


WHERE %cmake% >nul 2>nul
IF %ERRORLEVEL% NEQ 0 set cmake=%cmake_path%


GOTO :ParseParams

:ParseParams

    REM IF "%~1"=="" GOTO Main
    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help

    IF "%~1"=="/t" (
        SET target=%2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/b" (
        SET bitness=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/m" (
        SET mode=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/bt" (
        SET buildTools=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/mt" (
        SET mt=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/pdb" (
        SET pdb=1
        goto reParseParams
    )
    
    :reParseParams
    SHIFT
    if [%1]==[] goto main

GOTO :ParseParams


:main

set build_dir=build\%bitness%
if /i [%mode%]==[debug] set build_dir=build\debug\%bitness%

echo target=%target%
echo bitness=%bitness%
echo mode=%mode%
echo build_dir=%build_dir%
echo buildTools=%buildTools%

set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"

:build
    cmd /k "mkdir %build_dir% & %vcvars% & %cmake% -S . -B %build_dir% -DCMAKE_BUILD_TYPE=%mode% -DMT=%mt% -DPDB=%pdb% -G "NMake Makefiles" & %cmake% --build %build_dir% --config %mode% --target %target% & exit"

    if /i [%mode%]==[release] (
        certutil -hashfile %build_dir%/%target%.exe sha256 | find /i /v "sha256" | find /i /v "certutil" > %build_dir%/%target%.sha256
    )

    exit /B 0

:usage
    @echo Usage: %prog_name% [/t %target%^|%target%_shared] [/b 32^|64] [/m Debug^|Release] [/d C:\Build\Tools\] [/mt=no^|Debug^|Release] [/pdb] [/h]
    @echo Default: %prog_name% [/t %target% /b %bitness% /m %mode% /bt %buildTools%]
    exit /B 0
    
:help
    call :usage
    @echo.
    @echo Options:
    @echo /t The target name to build. Default: headerParser.
    @echo /b The target bitness. Default: 64.
    @echo /m The mode (Debug^|Release) to build in. Default: Release.
    @echo /bt Custom path to Microsoft Visual Studio BuildTools
    @echo /mt Statically include LIBCMT.lib. May be needed if a "VCRUNTIMExxx.dll not found Error" occurs on the target system. Default: no.
    @echo /pdb Include pdb symbols into release build.
    exit /B 0
