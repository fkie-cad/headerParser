@echo off

set my_name=%~n0
set my_dir="%~dp0"

set name=headerParser

set /a app=0
set /a lib=0
set /a tlib=0
set /a tplib=0

set /a bitness=64
set platform=x64
set mode=Release

set /a rtl=0
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

    IF /i "%~1"=="/app" (
        SET /a app=1
        goto reParseParams
    )
    IF /i "%~1"=="/lib" (
        SET /a lib=1
        goto reParseParams
    )
    IF /i "%~1"=="/tlib" (
        SET /a tlib=1
        goto reParseParams
    )
    IF /i "%~1"=="/tplib" (
        SET /a tplib=1
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
    IF /i "%~1"=="/rtl" (
        SET /a rtl=1
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

    set /a valid=0
    if [%bitness%] == [32] (
        set platform=x86
        set /a valid=1
    ) else (
        if [%bitness%] == [64] (
            set platform=x64
            set /a valid=1
        )
    )
    if %valid% == 0 (
        goto help
    )

    :: test valid targets
    set /a "valid=%app%+%lib%+%tlib%+%tplib%"
    if %valid% == 0 (
        set /a app=1
    )


    :: set runtime lib
    set rtlib=No
    set valid=0
    if /i [%mode%] == [debug] (
        if [%rtl%] == [1] (
            set rtlib=Debug
        )
        set pdb=1
        set valid=1
    ) else (
        if /i [%mode%] == [release] (
            if [%rtl%] == [1] (
                set rtlib=Release
            )
            set valid=1
        )
    )
    if [%valid%] == [0] (
        goto help
    )

    if [%verbose%] == [1] (
        echo app=%app%
        echo lib=%lib%
        echo bitness=%bitness%
        echo platform=%platform%
        echo mode=%mode%
        echo build_dir=%build_dir%
        echo buildTools=%buildTools%
        echo rtlib=%rtlib%
        echo pts=%pts%
        echo proj=%proj%
    )

    set vcvars=call :: pseudo nop command to prevent if else bug in :build
    :: WHERE %msbuild% >nul 2>nul
    :: IF %ERRORLEVEL% NEQ 0 set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"
    if [%VisualStudioVersion%] EQU [] (
        set vcvars="%buildTools:~1,-1%\VC\Auxiliary\Build\vcvars%bitness%.bat"
    )

    if %app% == 1 (
        call :build HeaderParser.vcxproj Application
    ) 
    if %lib% == 1 (
        call :build HeaderParser.vcxproj DynamicLibrary
    ) 
    if %tlib% == 1 (
        call :build tests\Tests.vcxproj Application TestLib
    ) 
    if %tplib% == 1 (
        call :build tests\Tests.vcxproj Application TestPELib
    ) 

    exit /b %errorlevel%

:build
    setlocal
        set proj=%1
        set ct=%2
        cmd /k "%vcvars% & msbuild %proj% /p:Platform=%platform% /p:PlatformToolset=%pts% /p:Configuration=%mode% /p:RuntimeLib=%rtlib% /p:PDB=%pdb% /p:ConfigurationType=%ct%  /p:DebugPrint=%dp%  & exit"

    endlocal
    exit /B %errorlevel%


:buildTest
    setlocal
        set proj=%1
        set ct=%2
        set target=%3

        cmd /k "msbuild %proj% /p:Platform=%platform% /p:Configuration=%mode% /p:RuntimeLib=%rtlib% /p:PDB=%pdb% /p:ConfigurationType=%ct% /p:TestTarget=%target% & exit"
        
    endlocal
    exit /B %errorlevel%


:usage
    echo Usage: %my_name% [/app] [/lib] [/b ^<bitness^>] [/m ^<mode^>] [/rtl] [/pdb] [/pts ^<toolset^>] [/bt ^<path^>] [/v] [/h]
::    echo Usage: %my_name% [/app] [/lib] [/b ^<bitness^>] [/m ^<mode^>] [/rtl] [/pdb] [/pts ^<toolset^>] [/bt ^<path^>] [/v] [/h]
    echo Default: %my_name% [/app /b %bitness% /m %mode% /bt %buildTools%]
    exit /B 0
    
:help
    call :usage
    echo.
    echo Targets:
    echo /app Build HeaderParser.exe application.
    echo /lib Build HeaderParser.dll library.
    echo.
    echo Options:
    echo /b Target bitness: 32^|64. Default: 64.
    echo /m Build mode: Debug^|Release. Default: Release.
    echo /rtl Statically include runtime libs. May be needed if a "VCRUNTIMExxx.dll not found Error" occurs on the target system.
    echo /pdb Include pdb symbols into release build. Default in debug mode. 
    echo /bt Custom path to Microsoft Visual Studio BuildTools
    echo /pts Platformtoolset. If WDK is not installed, set this to "v142". Default: "WindowsApplicationForDrivers10.0".
    echo.
    echo /v more verbose output
    echo /h print this

    exit /B 0
