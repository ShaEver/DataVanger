# DataVanger

> # 🚧 PROJETO INCOMPLETO — EM DESENVOLVIMENTO ATIVO 🚧
>
> **⚠️ Este projeto ainda está incompleto e está sendo continuamente melhorado.**
>
> Vários subsistemas estão implementados e testados, porém **ainda não ativados em
> produção** (backend libyara real, transporte HTTPS de update, serviço Windows,
> provedores ETW/AMSI reais). Aproximadamente **40% das capacidades** encontram-se
> no estado *Prepared / Stub / Needs-audit*. **Não use em ambiente de produção** e
> **não assuma que um módulo rotulado *Prepared/Stub* está ativo.** Consulte a
> seção [8. Active / Prepared / Stub](#8-active--prepared--stub-leia-antes-de-confiar-em-um-recurso)
> e a [Matriz de status dos módulos](docs/MODULE_STATUS_MATRIX.md) antes de confiar
> em qualquer recurso.

---

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
  + (Windows) proteção de chave por DPAPI CurrentUser; scanner, revisão, UI e realtime
  compartilham uma única composição. A restauração é verificada, assíncrona e **nunca
  automática**; itens V1 não autenticados não são restaurados. Origem usa handle/identidade
  estável, reparse points são recusados e o formato AEAD atual tem limite de 16 MiB.
- **Update assinado:** verificação RSA-PSS / ECDsa, anti-downgrade e transporte HTTPS
  limitado/fail-closed. Não existe fallback não assinado. PEM no appsettings é somente
  development/operator; produção ainda exige trust root vendor/admin autenticado.
- **IPC:** allowlist de comandos + validação de tamanho/caminho + DACL default-deny
  no host (named pipe).
- **Caches e caminhos:** hashes e Authenticode são revalidados no arquivo atual; JSON
  persistido é observação limitada, sem autoridade para pular scan ou conceder confiança.
  Diretórios de fornecedores são analisados no Fast Scan; localização não é allowlist.
- Realtime / serviço / ETW / AMSI estão **preparados, mas não ativados** em produção.

## 8. Active / Prepared / Stub (leia antes de confiar em um recurso)

| Capacidade | Estado |
|---|---|
| Scan sob demanda, pipeline de detecção, anti-FP, quarentena V2, agendador, reputação e publishers confiáveis configuráveis | **Active** |
| Backend libyara real (`#if YARA_REAL`, sem pacote ativo por padrão) | **Prepared (fallback p/ YARA leve)** |
| Transporte HTTPS assinado | **Prepared (development/operator; fail-closed)** |
| Serviço Windows e IPC conectado | **Disabled / Prepared** (instalação bloqueada; não há host conectado por padrão) |
| ETW / AMSI | **Prepared / Passive** (observe-only, default-off; não bloqueiam) |
| Memory scanner padrão | **Unavailable** (`NullMemoryReader`; não faz parte do scan por arquivo) |
| Monitor local da UI | **Passive** (vive somente enquanto a interface está aberta; monitora, não é proteção residente) |

## 9. Limitações conhecidas

- **Não há build/test verde verificado em ambiente não-Windows** (a toolchain exige
  Windows + .NET 8). Não reivindique milestone "STABLE" até `dotnet build
  DataVanger.sln` + `dotnet test` passarem no Windows.
- Aproximadamente **40% das capacidades** estão *Prepared / Stub / Needs-audit*
  (realtime, serviço, ETW/AMSI, trust root de produção para updates, memory/behavioral no scan).
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
