echo off
setlocal

set bin_path=
set label=Open with HeaderParser

set prog_name=%~n0
set user_dir="%~dp0"
set verbose=0

GOTO :ParseParams

:ParseParams

    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help

    IF "%~1"=="/p" (
        SET bin_path=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/l" (
        SET label=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/v" (
        SET verbose=1
        goto reParseParams
    )
    
    :reParseParams
        SHIFT
        if [%1]==[] goto main

GOTO :ParseParams


:main

    if ["%bin_path%"] == [] goto usage
    if ["%bin_path%"] == [""] goto usage
    if ["%label%"] == [] goto usage
    if ["%label%"] == [""] goto usage

    IF not exist "%bin_path%" (
        echo HeaderParser not found at "%bin_path%"!
        echo Place it there or adjust the bin_path.
        exit /b 0
    )

    if [%verbose%]==[1] (
        echo bin_path=%bin_path%
        echo label=%label%
    )

:add
    C:\Windows\System32\reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\*\shell\%label%\Command" /t REG_SZ /d "cmd /k %bin_path% \"%%1\" -i 2"

    endlocal
    exit /B 0


:usage
    echo Usage: %prog_name% /p "c:\bin\HeaderParser.exe" [/l "Open in HeaderParser"] [/v] [/h]
    exit /B 0

:help
    call :usage
    echo.
    echo /p Path to the HeaderParser binary. Must not have spaces at the moment!
    echo /l Label to show up in the context menu.
    echo /v Verbose mode.
    echo /h Print this.
    
    endlocal
    exit /B 0
