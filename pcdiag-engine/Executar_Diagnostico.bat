@echo off
setlocal enableextensions
title PC Diagnostic Engine

rem ============================================================
rem  PC Diagnostic Engine - atalho de execucao
rem
rem  REGRA DESTE ARQUIVO: nenhum bloco entre parenteses pode
rem  conter %VARIAVEL%.
rem
rem  O cmd expande as variaveis quando LE o bloco inteiro, antes
rem  de executar qualquer coisa. Se o valor contiver ")" - e
rem  contem sempre que a pasta se chama "PcDiag(2)", que e o
rem  nome que o navegador da ao segundo download do mesmo ZIP -
rem  esse parentese fecha o bloco no meio e o arquivo morre com
rem  "foi inesperado neste momento", ANTES de chegar ao pause.
rem  Para quem clicou: a janela pisca e fecha, e parece que o
rem  programa "nao abre". Por isso tudo aqui usa goto, e nunca
rem  if ( ) ou for ( ).
rem
rem  Outros cuidados que ja estavam aqui e continuam valendo:
rem   - cmd/powershell sao chamados por CAMINHO ABSOLUTO em
rem     %SystemRoot%\System32, nunca pelo PATH. Rodando de
rem     pendrive numa maquina possivelmente comprometida, o PATH
rem     nao e confiavel (PATH hijacking);
rem   - a elevacao e detectada com fltmc, que nao depende do
rem     servico LanmanServer estar ativo (o "net session" do
rem     launcher antigo falsa-negativava em maquinas com esse
rem     servico desligado, causando loop de elevacao).
rem ============================================================

set "SYS32=%SystemRoot%\System32"
set "TOOL=%~dp0bin\PcDiag.exe"
set "PCDIAG_SELF=%~f0"
set "PCDIAG_ARGS=%*"

if not exist "%TOOL%" goto sem_executavel

rem Verifica elevacao sem depender de servico nenhum.
"%SYS32%\fltmc.exe" >nul 2>&1
if errorlevel 1 goto elevar

rem Chamado com argumentos (dashboard, agendamento) nao pergunta nada.
if defined PCDIAG_ARGS goto executar_direto

:menu
echo.
echo ============================================================
echo   PC DIAGNOSTIC ENGINE
echo ============================================================
echo.
echo Somente leitura, exceto onde indicado. Nada e alterado na
echo configuracao deste computador.
echo.
echo   [1] Rapido        ~1 min    Inventario, SMART, eventos, seguranca.
echo                               Nenhuma carga - nao aquece o equipamento.
echo.
echo   [2] Completo      ~10 min   Tudo do rapido, mais 3 min de carga total
echo                               em todos os nucleos, 3 min de carga real
echo                               na GPU, teste de memoria e de disco.
echo                               RECOMENDADO.
echo.
echo   [3] Extremo       ~40 min   15 min de carga continua de CPU, 15 min
echo                               de carga real de GPU, 2 GB de memoria e
echo                               1 GB de disco verificados. Para defeito
echo                               intermitente que so aparece depois que a
echo                               maquina esquenta.
echo.
echo   [4] Personalizado           Escolher a duracao da carga.
echo.
echo Os perfis 2, 3 e 4 aquecem o equipamento de proposito e escrevem
echo um arquivo temporario no disco (removido ao final).
echo.

set "ESCOLHA="
set /p "ESCOLHA=Opcao [2]: "
if not defined ESCOLHA set "ESCOLHA=2"

if "%ESCOLHA%"=="1" goto perfil_rapido
if "%ESCOLHA%"=="2" goto perfil_completo
if "%ESCOLHA%"=="3" goto perfil_extremo
if "%ESCOLHA%"=="4" goto perfil_custom

echo.
echo Opcao invalida.
goto menu

:perfil_rapido
set "PERFIL=Rapido (somente leitura)"
set "PCDIAG_ARGS="
goto executar

:perfil_completo
set "PERFIL=Completo (carga de 3 min, CPU e GPU)"
set "PCDIAG_ARGS=--stress --stress-seconds 180 --memory-test --disk-benchmark --gpu-stress"
goto executar

:perfil_extremo
set "PERFIL=Extremo (carga de 15 min)"
set "PCDIAG_ARGS=--extremo --stress-seconds 900 --memory-test-mb 2048 --disk-benchmark-mb 1024"
goto executar

:perfil_custom
echo.
set "SEGUNDOS="
set /p "SEGUNDOS=Duracao da carga de CPU em segundos (5 a 7200) [300]: "
if not defined SEGUNDOS set "SEGUNDOS=300"

rem SEGUNDOS entra sem aspas na linha de comando do PcDiag.exe, ja
rem elevado. Por isso so aceita digitos puros aqui; qualquer outro
rem caractere cai no padrao de 300s em vez de ser usado.
echo %SEGUNDOS%| "%SYS32%\findstr.exe" /r "^[0-9][0-9]*$" >nul
if errorlevel 1 goto perfil_custom_invalido

set "PERFIL=Personalizado (carga de %SEGUNDOS% s, CPU e GPU)"
set "PCDIAG_ARGS=--stress --stress-seconds %SEGUNDOS% --memory-test --disk-benchmark --gpu-stress"
goto executar

:perfil_custom_invalido
echo.
echo Valor invalido - use somente numeros (sem espacos, letras ou simbolos).
echo Usando o padrao de 300 segundos.
set "PERFIL=Personalizado (carga de 300 s, CPU e GPU)"
set "PCDIAG_ARGS=--stress --stress-seconds 300 --memory-test --disk-benchmark --gpu-stress"
goto executar

:executar
echo.
echo ============================================================
echo   Perfil: %PERFIL%
echo ============================================================
echo.
echo Nao use o computador durante o teste: qualquer outro programa
echo pesado disputa CPU e distorce a medicao.
echo.
"%TOOL%" %PCDIAG_ARGS%
set "PCDIAG_EXIT=%ERRORLEVEL%"
goto fim

:executar_direto
"%TOOL%" %*
set "PCDIAG_EXIT=%ERRORLEVEL%"
goto fim

rem Os codigos abaixo espelham Entry.cs: 0 ok, 1 criticos encontrados,
rem 2 argumento invalido, 3 sistema nao suportado, 4 erro inesperado -
rem nunca imprima sucesso sem checar %ERRORLEVEL% primeiro.
:fim
echo.
if "%PCDIAG_EXIT%"=="0" goto fim_ok
if "%PCDIAG_EXIT%"=="1" goto fim_criticos
if "%PCDIAG_EXIT%"=="2" goto fim_arg_invalido
if "%PCDIAG_EXIT%"=="3" goto fim_nao_suportado
goto fim_erro

:fim_ok
echo Diagnostico concluido - nenhum item critico encontrado.
goto fim_pause

:fim_criticos
echo Diagnostico concluido - foram encontrados itens CRITICOS. Veja o laudo.
goto fim_pause

:fim_arg_invalido
echo ERRO: argumento invalido passado ao PcDiag.exe (codigo 2). Nenhum laudo foi gerado.
goto fim_pause

:fim_nao_suportado
echo ERRO: este sistema operacional nao e suportado pela ferramenta (codigo 3). Nenhum laudo foi gerado.
goto fim_pause

:fim_erro
echo ERRO: o PcDiag.exe encerrou de forma inesperada (codigo %PCDIAG_EXIT%). Nenhum laudo confiavel foi gerado - veja os logs, se houver.
goto fim_pause

:fim_pause
echo Pressione qualquer tecla para fechar.
pause >nul
exit /b %PCDIAG_EXIT%

:sem_executavel
echo.
echo ERRO: PcDiag.exe nao encontrado em:
echo   %TOOL%
echo.
echo A pasta bin\ precisa estar ao lado deste arquivo. Se voce extraiu
echo um ZIP, confira se extraiu a pasta inteira - e nao apenas o .bat.
echo.
echo Para compilar a ferramenta:
echo   powershell -ExecutionPolicy Bypass -File "%~dp0build.ps1"
echo.
pause
exit /b 1

:elevar
echo.
echo Solicitando privilegios de administrador...
echo.
echo Sem elevacao o laudo sai incompleto: temperatura, sensores, SMART,
echo eventos do Windows e BitLocker ficam marcados como REQUER ADMIN, e
echo o teste de carga nao consegue medir temperatura nenhuma.
echo.

rem O caminho e os argumentos vao por variavel de ambiente, nao dentro
rem da linha de comando: caminho com aspas simples, parenteses ou acento
rem quebraria a string do PowerShell, e e exatamente esse tipo de pasta
rem (Downloads\PcDiag(2)) que aparece na pratica.
rem
rem -ErrorAction Stop e obrigatorio: quando o UAC e negado, Start-Process
rem reporta a falha como erro NAO terminante e o powershell.exe voltaria
rem com codigo 0 mesmo assim - o "if errorlevel 1" nunca dispararia e a
rem janela fecharia sem aviso nenhum.
"%SYS32%\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$o=@{FilePath=$env:PCDIAG_SELF; Verb='RunAs'; ErrorAction='Stop'}; if ($env:PCDIAG_ARGS) { $o['ArgumentList']=$env:PCDIAG_ARGS }; Start-Process @o"
if errorlevel 1 goto elevar_falhou
exit /b 0

:elevar_falhou
echo.
echo ERRO: nao foi possivel solicitar elevacao de administrador.
echo Isso acontece quando o UAC e negado/cancelado, ou esta bloqueado por
echo politica de grupo ou antivirus.
echo.
echo Tente rodar manualmente como administrador: clique com o botao direito
echo em Executar_Diagnostico.bat e escolha "Executar como administrador".
echo.
pause
exit /b 1
