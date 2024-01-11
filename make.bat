@ECHO OFF

pushd %~dp0

REM Command file for aiobastion publication
REM To execute this script you need twine (pip install twine) and build (pip install build)


if "%PYTHON%" == "" (
	set PYTHON=py
)

if "%TWINE%" == "" (
    set TWINE=twine.exe
)

for /f "eol=- delims=" %%a in (repo.conf) do set "%%a" 2> NUL
if not "%proxy%" == "" (
    set HTTPS_PROXY=%proxy%
)

set dist_folder=".\dist"
rmdir %dist_folder% /s /q

%PYTHON% -m build --no-isolation
%TWINE% upload --repository artifactory dist/* --config-file .\repo.conf
