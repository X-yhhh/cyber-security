@echo off
rem P3-B controlled runner: matrix fitting stays disabled; B5R is the single authorized reproduction (budget 33).
cd /d "%~dp0.."
set PYTHONUNBUFFERED=1
set PYTHONPATH=src
set P3B_ROOT=.cache\p3b-20261007
if /I "%1"=="B0" goto B0
if /I "%1"=="B1" goto B1
if /I "%1"=="B2" goto B2
if /I "%1"=="B3" goto B3
if /I "%1"=="B4" goto B4
if /I "%1"=="B5" goto B5
if /I "%1"=="B5R" goto B5R
echo unknown step=%1
exit /b 2
:B0
echo Existing preregistration is preserved. The cumulative fitting budget is exhausted.
exit /b 2
:B1
".venv\Scripts\python.exe" -m unittest tests.test_multiclass_train tests.test_multiclass_audit tests.test_multiclass_reproduce -v
exit /b %ERRORLEVEL%
:B2
echo Fitting disabled: cumulative budget exceeded. Preserve every prior run.
exit /b 2
:B3
echo Original policyPreview is invalid. Use multiclass_audit with a fresh output directory.
exit /b 2
:B4
echo Use corrected audit evidence. Original attackDetection used class recall.
exit /b 2
:B5
echo B5 original run lacks native model; use B5R reproduction evidence.
exit /b 2
:B5R
".venv\Scripts\python.exe" -m cyber_training.host_guard.multiclass_reproduce fit --run %P3B_ROOT%\run-reproduce-v1 --reference-run %P3B_ROOT%\run-main-v3 --reference-outputs %P3B_ROOT%\audit-windows-v1 --ledger %P3B_ROOT%\fit-ledger.jsonl --inventory %P3B_ROOT%\fit-inventory.json --frozen %P3B_ROOT%\frozen --sidecars %P3B_ROOT%\sidecars > %P3B_ROOT%\run-reproduce-v1.log 2> %P3B_ROOT%\run-reproduce-v1.err
exit /b %ERRORLEVEL%
