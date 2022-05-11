@echo off

set prog_name=%~n0
set user_dir="%~dp0"

set name=headerParser
set target=%name%
set ct=Application

set /a bitness=64
set platform=x64
set mode=Release

set /a rt=0
set /a dp=0
set pdb=0

set buildTools="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\"
set pts=WindowsApplicationForDrivers10.0
set verbose=0


:: default
if [%1]==[] goto main


GOTO :ParseParams

:ParseParams

    REM IF "%~1"=="" GOTO Main
    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help

    IF /i "%~1"=="/t" (
        SET target=%2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/b" (
        SET /a bitness=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/m" (
        SET mode=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/bt" (
        SET buildTools=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/pts" (
        SET pts=%~2
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/rt" (
        SET /a rt=1
        goto reParseParams
    )
    IF /i "%~1"=="/pdb" (
        SET /a pdb=1
        goto reParseParams
    )
    IF /i "%~1"=="/dp" (
        SET /a dp=1
        goto reParseParams
    )
    
    IF /i "%~1"=="/v" (
        SET verbose=1
        goto reParseParams
    ) ELSE (
        echo Unknown option : "%~1"
    )
    
    :reParseParams
    SHIFT
    if [%1]==[] goto main

GOTO :ParseParams



:main

    set build_dir=build\%bitness%
    if /i [%mode%]==[debug] set build_dir=build\debug\%bitness%

    set valid=0
    if [%bitness%] == [32] (
        set platform=x86
        set valid=1
    ) else (
        if [%bitness%] == [64] (
            set platform=x64
            set valid=1
        )
    )
    if [%valid%] == [0] (
        goto help
    )
    :: test valid targets
    set valid=0
    set test=0
    if /i [%target%] == [%name%] (
        set valid=1
        set proj=HeaderParser.vcxproj
    )
    if /i [%target%] == [%name%_lib] (
        set valid=1
        set proj=HeaderParser.vcxproj
    )
    if /i [%target%] == [TestLib] (
        set test=1
        set valid=1
        set proj=tests\Tests.vcxproj
    )
    if /i [%target%] == [TestPELib] (
        set test=1
        set valid=1
        set proj=tests\Tests.vcxproj
    )
    if [%valid%] == [0] (
        goto help
    )

    :: set ConfigurationType
    set ct=Application
    if /i [%target%] == [%name%_lib] (
        set ct=DynamicLibrary
    )

    :: set runtime lib
    set rtlib=No
    set valid=0
    if /i [%mode%] == [debug] (
        if [%rt%] == [1] (
            set rtlib=Debug
        )
        set pdb=1
        set valid=1
    ) else (
        if /i [%mode%] == [release] (
            if [%rt%] == [1] (
                set rtlib=Release
            )
            set valid=1
        )
    )
    if [%valid%] == [0] (
        goto help
    )

    if [%verbose%] == [1] (
        echo target=%target%
        echo ConfigurationType=%ct%
        echo bitness=%bitness%
        echo platform=%platform%
        echo mode=%mode%
        echo build_dir=%build_dir%
        echo buildTools=%buildTools%
        echo rtlib=%rtlib%
        echo pts=%pts%
        echo proj=%proj%
    )

    set vcvars=""
    :: WHERE %msbuild% >nul 2>nul
    :: IF %ERRORLEVEL% NEQ 0 set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"
    if [%VisualStudioVersion%] EQU [] (
        set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"
    )

    if [%test%] == [0] (
        goto build
    ) else (
        goto buildTest
    )

:build
    cmd /k "%vcvars% & msbuild %proj% /p:Platform=%platform% /p:PlatformToolset=%pts% /p:Configuration=%mode% /p:RuntimeLib=%rtlib% /p:PDB=%pdb% /p:ConfigurationType=%ct%  /p:DebugPrint=%dp%  & exit"

    exit /B 0

:buildTest
    if [%vcvars%] EQU [] ( 
        cmd /k "msbuild %proj% /p:Platform=%platform% /p:Configuration=%mode% /p:RuntimeLib=%rtlib% /p:PDB=%pdb% /p:ConfigurationType=%ct% /p:TestTarget=%target% & exit"
    ) else (
        cmd /k "%vcvars% & msbuild %proj% /p:Platform=%platform% /p:Configuration=%mode% /p:RuntimeLib=%rtlib% /p:PDB=%pdb% /p:ConfigurationType=%ct% /p:TestTarget=%target% & exit"
    )

    exit /B 0

:usage
    echo Usage: %prog_name% [/t %name%^|%name%_lib] [/b 32^|64] [/m Debug^|Release] [/rt] [/pdb] [/bt C:\Build\Tools\] [/v] [/h]
    echo Default: %prog_name% [/t %target% /b %bitness% /m %mode% /bt %buildTools%]
    exit /B 0
    
:help
    call :usage
    echo.
    echo Options:
    echo /t Target to build: %name%^|%name%_lib. Default: %name%.
    echo /b Target bitness: 32^|64. Default: 64.
    echo /m Build mode: Debug^|Release. Default: Release.
    echo /rt Statically include LIBCMT.lib. May be needed if a "VCRUNTIMExxx.dll not found Error" occurs on the target system.
    echo /pdb Include pdb symbols into release build. Default in debug mode. 
    echo /bt Custom path to Microsoft Visual Studio BuildTools
    echo /pts Platformtoolset. If WDK is not installed, set this to "v142". Default: "WindowsApplicationForDrivers10.0".
    echo.
    echo /v more verbose output
    echo /h print this
    exit /B 0
