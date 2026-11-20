@echo off
setlocal
cd /d "%~dp0"
title Elisha
set PY=
where py >nul 2>nul && set PY=py
if not defined PY where python >nul 2>nul && set PY=python
if not defined PY goto nopython

if exist ".elisha_ready" goto run
echo First run: installing the radio tools. This needs internet one time and takes about a minute.
echo.
%PY% -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto failed
echo ok> .elisha_ready

:run
echo Starting Elisha. Your browser will open. Leave this window open while you use it.
%PY% elisha.py
echo.
echo Elisha stopped.
pause
exit /b 0

:nopython
echo Python was not found on this computer.
echo Install it from https://www.python.org/downloads/ and tick the box that says Add python.exe to PATH.
echo Then double click this file again.
pause
exit /b 1

:failed
echo.
echo The install did not finish. Take a screenshot of this window and send it over.
pause
exit /b 1
