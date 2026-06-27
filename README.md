# DataVanger

**DataVanger** é uma suíte de segurança / anti-malware para **Windows desktop**
(interface WPF + serviço de fundo) construída em **.NET 8**, com foco em
**detecção de alta confiança sob um contrato estrito anti-falso-positivo**: a
heurística sozinha nunca produz veredito de "malware confirmado" nem dispara uma
ação destrutiva automática.

Capacidades: varredura de arquivos sob demanda e agendada, correspondência YARA
leve, análise de PE / scripts / arquivos compactados / documentos / extensões de
navegador, pontuação de reputação, quarentena segura (criptografada) e remediação
reversível.

> **Honestidade de status:** vários subsistemas estão **implementados e testados**,
> mas **ainda não ativados em produção** (libyara real, transporte HTTP de update,
> serviço Windows, provedores ETW/AMSI reais). Cada módulo é rotulado
> **Active / Prepared / Fallback / Stub / Disabled / Needs audit** para que nada seja
> super-anunciado. Não assuma que um módulo *Prepared/Stub* está ativo.

> **Código-fonte:** versionado como árvore de arquivos na raiz deste repositório
> (a solução `DataVanger.sln` e os 6 projetos). Os comandos abaixo são executados
> a partir da raiz do repositório. Um workflow de **CI no Windows**
> (`.github/workflows/ci.yml`) roda build + testes + checagem de invariantes a cada
> push/PR.

---

## 1. Plataforma e requisitos

- **Sistema operacional:** Windows (10/11). Recursos como DPAPI (chave de
  quarentena), ETW e ACLs de named pipe são específicos do Windows.
- **SDK:** **.NET 8 SDK**.
- Os projetos `DataVanger`, `DataVanger.Service` e `DataVanger.Tests` têm alvo
  `net8.0-windows` e **não compilam em Linux/macOS**.

## 2. Estrutura dos 6 projetos

| Projeto | TFM | Tipo | Papel |
|---|---|---|---|
| `DataVanger` | net8.0-windows | WinExe (WPF+WinForms) | UI, motor de scan, módulos de detecção, adapters |
| `DataVanger.Engine` | net8.0 | classlib | Quarentena V2, verificação de update assinado, decisão realtime, protected-files, agregador de status |
| `DataVanger.Infrastructure` | net8.0 | classlib | IPC por named pipe, provedores ETW, chave de quarentena DPAPI, watchers de arquivo |
| `DataVanger.Service` | net8.0 | Exe | Host de serviço + handlers IPC (`--service` é stub diagnóstico) |
| `DataVanger.Shared` | net8.0 | classlib | Contratos / DTOs / enums compartilhados |
| `DataVanger.Tests` | net8.0-windows | xUnit | Suíte de testes (mega-teste de paridade legada + suítes focadas) |

Grafo de dependências unidirecional, sem ciclos: `Engine`, `Infrastructure` e a UI
referenciam apenas `DataVanger.Shared`; `Service` referencia todos os anteriores.

## 3. Build (PowerShell)

```powershell
dotnet build DataVanger.sln
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
```

## 4. Testes (PowerShell)

```powershell
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~AntiFalsePositive"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Publisher"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Yara"
```

## 5. Comandos de validação de invariantes (PowerShell)

Rode a partir da raiz da árvore de código extraída. O resultado esperado de cada
comando é **vazio** (nenhuma linha).

```powershell
# (a) zero blocos catch anônimos / vazios
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'catch\s*\{\s*\}'

# (b) zero locks no objeto 'qm' (padrão de lock proibido)
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'lock\s*\(qm\)'

# (c) zero arquivos .cs com CRLF (apenas LF)
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  ForEach-Object { $c = Get-Content $_.FullName -Raw; if ($c -match "`r") { $_.FullName } }
```

Esperado: **zero** catch anônimos · **zero** `lock(qm)` · **zero** `.cs` com CRLF.

## 6. Contrato anti-falso-positivo

Aplicado em `DataVanger/Core/ThreatClassificationPolicy.cs` e
`Classification/AntiFalsePositivePolicy.cs`:

- **`ConfirmedMalware` apenas** quando o hash é conhecido como malicioso
  (`IsBlacklisted`) **ou** há assinatura confirmada (`HasConfirmedSignature` — ex.:
  regra YARA curada marcada explicitamente como `confirmed`).
- **Evidência heurística** é **limitada a `HighRisk`** — nunca `ConfirmedMalware`.
- **Quarentena automática só ocorre para `ConfirmedMalware`** (com gate de score).
- Publisher confiável **nunca** sobrepõe um hash conhecido como malicioso. A
  verificação de publisher atual é um *match de substring case-insensitive* do
  subject do certificado (**ainda não** validação de cadeia/thumbprint — *a
  endurecer*).

## 7. Postura de segurança (resumo)

- **Quarentena V2:** AES-256-GCM (criptografia autenticada) + integridade HMAC-SHA256
  + (Windows) proteção de chave por DPAPI; restauração verificada por integridade e
  **nunca automática**.
- **Update assinado:** verificação RSA-PSS / ECDsa com anti-downgrade implementada; o
  **transporte HTTP é stub** (lança) — apenas transportes em arquivo/memória funcionam.
- **IPC:** allowlist de comandos + validação de tamanho/caminho + DACL default-deny
  no host (named pipe).
- Realtime / serviço / ETW / AMSI estão **preparados, mas não ativados** em produção.

## 8. Active / Prepared / Stub (leia antes de confiar em um recurso)

| Capacidade | Estado |
|---|---|
| Scan de arquivos, pipeline de detecção, anti-FP, quarentena V2, agendador, YARA leve, reputação, publishers confiáveis configuráveis | **Active** |
| Backend libyara real (`#if YARA_REAL`, sem pacote ativo por padrão) | **Prepared (fallback p/ YARA leve)** |
| Transporte HTTP de update assinado (`HttpUpdateTransport` lança) | **Stub** |
| Serviço Windows (`--service` é stub diagnóstico) | **Stub** |
| Provedores ETW / AMSI comportamentais | **Prepared / Stub** |
| Memory scanner / motor comportamental no scan por arquivo | **Needs audit** (existem + testados, mas não ligados ao `EngineComposition`) |

## 9. Limitações conhecidas

- **Não há build/test verde verificado em ambiente não-Windows** (a toolchain exige
  Windows + .NET 8). Não reivindique milestone "STABLE" até `dotnet build
  DataVanger.sln` + `dotnet test` passarem no Windows.
- Aproximadamente **40% das capacidades** estão *Prepared / Stub / Needs-audit*
  (realtime, serviço, ETW/AMSI, transporte HTTP de update, memory/behavioral no scan).
- Sem CI/CD automatizado; a validação é manual (PowerShell + `dotnet`).

## 10. Integração contínua

`.github/workflows/ci.yml` roda em `windows-latest` a cada push nas branches
`main`/`claude/**` e em PRs para `main`:

1. `dotnet restore` + `dotnet build DataVanger.sln` (Release);
2. `dotnet test DataVanger.Tests`;
3. checagem das invariantes (passo (a)/(b)/(c) da seção 5) em PowerShell —
   falha o build se houver `catch` anônimo, `lock(qm)` ou `.cs` com CRLF.

## 11. Documentação

- [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) — execução, configurações,
  comportamento de scan/quarentena/agendador/realtime/update/serviço.
- [`docs/DEVELOPER_GUIDE.md`](docs/DEVELOPER_GUIDE.md) — layout, pipeline de detecção,
  como adicionar módulos/testes, invariantes, regras de segurança.
- [`docs/MODULE_STATUS_MATRIX.md`](docs/MODULE_STATUS_MATRIX.md) — status por módulo
  com referências de arquivo.
- [`docs/SIGNED_UPDATES_OPERATOR_GUIDE.md`](docs/SIGNED_UPDATES_OPERATOR_GUIDE.md) — como
  publicar e configurar um feed de assinaturas assinado (chaves, manifesto, HTTPS, settings).
- [`docs/README_ORIGINAL_EN.md`](docs/README_ORIGINAL_EN.md) — README técnico
  original (em inglês).
- [`ANALISE_PROS_E_CONTRAS.md`](ANALISE_PROS_E_CONTRAS.md) — análise de pontos
  positivos e negativos do projeto.
