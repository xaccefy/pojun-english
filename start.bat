@echo off
rem Switch the console to UTF-8, otherwise the text in this file shows as garbage
rem in a GBK terminal.
chcp 65001 >nul 2>&1
rem ARTEX watchdog start script (Windows)
rem
rem Usage:
rem   start.bat                  run in foreground (Ctrl-C to stop)
rem   start.bat -addr :9000      extra args are passed through to artex verbatim
rem
rem It does exactly one thing: run artex.exe, then decide from the exit code
rem whether to launch it again.
rem
rem   0      clean user stop        -> exit the loop
rem   75     program asked restart  -> rerun immediately (user clicked
rem                                    "one-click update" or "rollback" in the UI)
rem   other  crash                  -> rerun after backoff (1->2->4... up to 60s)
rem
rem Download, SHA256 verification and binary swap do not live here — artex does
rem all of that itself at startup (the selfupdate package). This script stays
rem deliberately dumb; see the notes at the top of start.sh for details.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=artex.exe"
if not exist "%BIN%" (
	echo [artex] executable %BIN% not found 1>&2
	exit /b 1
)

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [artex] exited normally
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	rem Update/rollback is staged: rerunning artex applies the swap at startup.
	echo [artex] restart requested (applying new version)...
	set /a delay=1
	goto loop
)

echo [artex] abnormal exit ^(code=!code!^), restarting in !delay!s 1>&2
rem `timeout` fails in a redirected console; use ping as fallback
rem (delaying N seconds takes N+1 pings).
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
