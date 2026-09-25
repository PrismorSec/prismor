@echo off
rem Windows twin of the sh guard in the committed dogfood hook configs (#495).
rem Runs under cmd.exe and PowerShell alike. Picks the first python that can
rem import yaml, so a Microsoft Store "python" stub or a bare interpreter is skipped.
if "%PRISMOR_DOGFOOD%"=="0" exit /b 0
set "PY=%PRISMOR_DEV_PYTHON%"
if not defined PY for %%c in (python py python3) do if not defined PY %%c -c "import yaml" <nul >nul 2>&1 && set "PY=%%c"
if not defined PY (
  echo prismor dogfood: no python with pyyaml found ^(pip install pyyaml, or set PRISMOR_DEV_PYTHON^) 1>&2
  exit /b 2
)
"%PY%" "%~dp0dev-hook.py" %*
exit /b %ERRORLEVEL%
