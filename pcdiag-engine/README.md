# PcDiag Engine (versao comunitaria)

Esta e uma versao de codigo aberto do motor de diagnostico do PcDiag/TechBroswer:
o mesmo pipeline de coleta, cross-check, analise e pontuacao de confianca
descrito no [README do projeto](../README.md), **sem nenhuma integracao com
o dashboard comercial**. Esta build nunca envia o laudo para lugar nenhum:
ela roda inteiramente local e grava o resultado em `bin\Relatorios\`.

Licenca: [PolyForm Noncommercial 1.0.0](LICENSE.md). Voce pode ver, compilar,
rodar, estudar e propor mudancas (pull requests bem-vindos); uso comercial
proprio (incluindo incorporar isto num produto ou servico pago) nao e
permitido sob esta licenca.

## Por que existe uma versao separada

O produto comercial (TechBroswer) integra este motor com um dashboard SaaS
que recebe os laudos, calcula historico e dispara alertas para tecnicos.
Essa parte comercial nao esta aqui. O que esta aqui e o motor de diagnostico
em si: a parte que qualquer pessoa pode rodar no proprio computador para ver
exatamente o que ele mede e como ele decide o que reportar.

## Como compilar

Nao precisa de .NET SDK, MSBuild nem Visual Studio: usa o compilador C# que
ja vem no Windows (parte do .NET Framework 4.x). Qualquer Windows 10/11
compila sem instalar nada.

```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```

Depois:

```bash
bin\PcDiag.exe
```

Ou duplo clique em `Executar_Diagnostico.bat` (pede elevacao de administrador
para os testes que precisam dela).

O laudo sai em `bin\Relatorios\<EQUIPAMENTO>_<data>\` (`report.html` e
`report.json`, mais os logs de execucao). Veja as opcoes de linha de comando
no [README do motor original](../../DiagnosticEngine/README.md) -- as flags
sao as mesmas, exceto pelo que foi removido (envio ao dashboard).

### Rodando a suite de testes

```bash
powershell -ExecutionPolicy Bypass -File build.ps1 -Tests
```

### Sensores de hardware (opcional)

Para leitura de temperatura/RPM, baixe o
[LibreHardwareMonitorLib](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor)
e coloque os `.dll` numa pasta `lib\` na raiz deste projeto antes de compilar.
Sem isso, a ferramenta roda normalmente e reporta "sensores indisponiveis".

## O que foi removido em relacao ao motor comercial

- `Reporting/DashboardSender.cs` e o envio automatico do laudo ao final do
  scan -- esta build nunca faz nenhuma chamada de rede alem das sondagens de
  conectividade opcionais (`--no-connectivity` desliga ate essas).
- Sincronizacao do pacote de build com o dashboard (`build.ps1`).
- Comentarios que faziam referencia a itens internos de auditoria de
  seguranca -- o codigo e o mesmo, mas o historico de bugs internos do
  produto comercial nao faz parte deste repositorio.

## Contribuindo

Pull requests sao bem-vindos: correcoes de bug, novos testes, suporte a mais
hardware, melhorias de precisao nos testes de diagnostico. Antes de abrir um
PR grande, abra uma issue descrevendo a mudanca proposta.

Regras do projeto que valem para qualquer contribuicao:

- **Ausencia de dado nunca vira aprovacao.** Se algo nao pode ser medido, o
  resultado e `NOT_TESTED`/`UNKNOWN`, nunca um "aprovado" por omissao.
- **Um Collector nunca produz status; um Test nunca toca o sistema
  operacional.** E isso que permite testar a logica de diagnostico contra
  inventarios sinteticos, sem hardware real.
- Codigo em C# 5 puro (o compilador in-box e pre-Roslyn): sem interpolacao
  de string, sem `?.`, sem `nameof`, sem membros com corpo de expressao.
  `async/await` e LINQ funcionam normalmente.
- Todo fonte em ASCII puro.

Rode `build.ps1 -Tests` antes de abrir o PR -- ele compila e roda a suite
inteira, e falha o build se algum teste quebrar.
