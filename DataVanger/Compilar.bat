@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title DataVanger - Compilando...

cd /d "%~dp0"

echo.
echo  =============================================
echo   DataVanger v2.0 - Gerador de executavel
echo  =============================================
echo.
echo  Pasta: %~dp0
echo.

:: Verifica se o .NET SDK esta instalado
where dotnet >nul 2>&1
if %errorlevel% NEQ 0 (
    echo  [ERRO] .NET 8 SDK nao encontrado no PATH.
    echo.
    echo  Solucao:
    echo  1. Baixe em: https://dotnet.microsoft.com/download/dotnet/8.0
    echo  2. Instale o ".NET SDK" para Windows x64
    echo  3. FECHE e reabra este .bat apos instalar
    echo.
    pause
    exit /b 1
)

echo  .NET SDK encontrado:
dotnet --version
echo.

:: Gera o icone app.ico se nao existir
if not exist "app.ico" (
    echo  Gerando icone app.ico...
    powershell -NoProfile -ExecutionPolicy Bypass -File "GerarIcone.ps1" >nul 2>&1
    if not exist "app.ico" (
        echo  [AVISO] Icone nao gerado. O build continuara sem icone personalizado.
    ) else (
        echo  Icone gerado com sucesso.
    )
    echo.
)

:: Limpa publicacao anterior
if exist "Publicar" (
    echo  Limpando build anterior...
    rd /s /q "Publicar"
)

echo  Compilando... aguarde 1-2 minutos...
echo.

dotnet publish "DataVanger.csproj" ^
    -r win-x64 ^
    -c Release ^
    -p:PublishSingleFile=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    --self-contained ^
    -o "Publicar" ^
    --nologo 2>&1

set BUILD_RESULT=%errorlevel%

if %BUILD_RESULT% NEQ 0 (
    echo.
    echo  =============================================
    echo   [ERRO] Compilacao falhou - codigo %BUILD_RESULT%
    echo  =============================================
    echo.
    echo  Leia a mensagem de erro acima e tente:
    echo  - Verificar se o .NET 8 SDK esta instalado corretamente
    echo  - Fechar e reabrir o terminal apos instalar o SDK
    echo  - Rodar como Administrador se houver erro de permissao
    echo.
    pause
    exit /b %BUILD_RESULT%
)

echo.
echo  =============================================
echo   SUCESSO! DataVanger.exe gerado.
echo  =============================================
echo.
echo  Local: %~dp0Publicar\DataVanger.exe
echo.
echo  Copie DataVanger.exe para qualquer pasta e execute.
echo  Nao precisa de instalacao nem de PowerShell.
echo.

start "" explorer "%~dp0Publicar"
pause
