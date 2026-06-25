# Roadmap de Melhorias — Profundidade de Scan, Velocidade, Eliminação de Vírus e Limpeza

> **Contexto.** Este plano consolida e estende o trabalho já existente. O projeto já
> possui um roadmap de performance de 15 fases em
> [`ANALISE_COMPLETA_ARQUITETURA_SCAN_E_PLANO_CORRECAO.md`](ANALISE_COMPLETA_ARQUITETURA_SCAN_E_PLANO_CORRECAO.md)
> (com partes **já implementadas**) e a análise de regressão de performance em
> [`STANDARD_SCAN_SLOWDOWN_AND_JUDGMENT_ANALYSIS.md`](STANDARD_SCAN_SLOWDOWN_AND_JUDGMENT_ANALYSIS.md).
> Aqui o foco são as dimensões que o usuário pediu e que aqueles docs cobrem menos:
> **profundidade de detecção, eliminação de vírus, limpeza de lixo** e a **correção
> dos erros de julgamento (falsos positivos)** — tudo ancorado no código atual.
>
> Legenda de prioridade: **P0** = destrava valor central / corrige algo quebrado ·
> **P1** = alto impacto · **P2** = incremental. Esforço: P (pequeno) / M (médio) / G (grande).

---

## 0. O achado mais importante (lê antes de tudo)

Pela análise existente do projeto, **nenhuma base de assinaturas/YARA é carregada por
padrão** — o scanner roda **"cego"**: 0 hashes conhecidos, 0 regras confirmadas, então
**nunca** emite `ConfirmedMalware` e **nunca** quarentena automaticamente
(`STANDARD_SCAN_SLOWDOWN…` item J-1; toda a saída é heurística Suspect/HighRisk). Isso
afeta **detecção, eliminação e falsos positivos ao mesmo tempo**. Resolver isto é o
item de maior alavancagem do roadmap inteiro — aparece como **A0/B1/C1** abaixo.

---

## A. Velocidade / eficiência de scan

O roadmap de 15 fases já endereça isto. Estado real pelo código:

| Item do plano de 15 fases | Estado | Observação |
|---|---|---|
| Fase 2 — dedup de alvos por subsunção de prefixo | ✅ **Feito** | `Engine/TargetDiscovery.cs:RemoveContainedPaths` |
| Cache de confiança de assinatura (catálogo gated) | ✅ **Feito** | `SignatureTrustCache`/`trust_cache.json` |
| Fase 4 — **cache de resultado de detecção** | ❌ Pendente | só há cache de hash; arquivo inalterado é re-analisado pelos 9 módulos |
| Fase 6 — paralelismo adaptativo | ❌ Pendente | hoje é semáforo fixo + `Task.Delay` constante; CPU subutilizada |
| Fase 1 — telemetria de performance wired | ⚠️ Parcial | `DeepScanTelemetry` existe, não está na hot path |
| Fase 11 — pular diretórios "lixo de build" | ❌ Pendente | `node_modules`, `__pycache__`, `bin/obj`, caches |
| Fase 5/9 — auto-whitelist por publisher/reputação | ⚠️ Parcial | alívio de publisher funciona; falta skip de análise |

**Prioridades pendentes (recomendadas, em ordem):**

- **A1 (P0, G) — Cache de resultado de detecção.** Chave `(path, LastWriteUtc, length)` →
  `PipelineOutcome`; bypass obrigatório para hash malicioso / assinatura confirmada;
  invalidar ao atualizar feed de assinaturas. Maior ganho em rescans (50–70%). É a
  Fase 4 do plano existente — priorizar.
- **A2 (P1, M) — Skip de caminhos de baixíssimo sinal.** Lista `node_modules/`,
  `__pycache__/`, `.gradle/`, `bin/`, `obj/`, `dist/` + contador transparente
  ("N diretórios de cache pulados"). Enorme em máquinas de dev. Fase 11.
- **A3 (P1, G) — Paralelismo adaptativo.** Ajustar nº de workers por CPU%/latência de
  disco/RAM em vez de semáforo fixo; meta 33%→70% de CPU. Fase 6.
- **A4 (P1, M) — Telemetria por estágio na hot path.** Sem baseline mensurável as
  otimizações são "chute". Fase 1. Habilita medir A1–A3.
- **A5 (P2, M) — I/O: buffer pooling + leitura única.** `ArrayPool<byte>`, hash em
  streaming, reaproveitar buffer de magic-bytes; reduzir 3–5 aberturas/arquivo. Fase 3.
- **A6 (P2, M) — Diferenciação real de perfis + gating por tipo de arquivo.** Quick =
  hash+heurística em caminhos críticos; Full = todos os módulos porém *gated* por tipo
  (não rodar PE em `.txt`). Fases 7/8 (parcialmente já refletido em
  `Detection/DetectionModuleSet.FastOnly`).

---

## B. Profundidade de detecção

Onde o produto é mais raso hoje (confirmado no código): motor comportamental e de
memória **existem e têm testes mas não estão ligados** ao `Engine/EngineComposition`;
YARA ativo é só de strings; sem unpacking/emulação; entropia de PE é descritiva
(`ScoreDelta=0`).

- **B1 (P0, G) — Carregar feed de assinaturas + pacote YARA por padrão** (ver §0).
  Inclui base de hashes maliciosos conhecidos + regras YARA `confirmed`, com um aviso
  visível "0 assinaturas carregadas" quando ausente.
- **B2 (P0, M) — Ligar Memory scanner e Behavioral engine ao pipeline/serviço.** Já
  implementados/testados (`Behavioral/BehavioralCorrelationEngine.cs`, `Memory/*`),
  mas dormentes. Decidir o ponto de entrada (scan profundo e/ou serviço realtime) e
  wire — entrega profundidade comportamental real (ex.: "processo dropou binário e
  criou persistência"). Mantém contrato anti-FP (evidência, não confirma sozinho).
- **B3 (P1, G) — Ativar libyara real** (`#if YARA_REAL`) com fallback garantido, para
  padrões de bytes/wildcards/regex que o matcher leve não faz. Fase 12 candidata.
- **B4 (P1, M) — Unpacking antes da análise estática.** Ao menos UPX; detectar packer
  (já há nomes de seção UPX/Themida/VMP) e desempacotar para reanalisar.
- **B5 (P1, M) — Semântica de PE mais rica.** `imphash`, anomalias de recursos, overlay
  pontuado, metadados .NET, detecção de RWX já existe — somar import-table suspeita e
  TLS callbacks. Manter entropia como sinal observacional.
- **B6 (P2, M) — Cobertura de superfícies novas.** ADS (Alternate Data Streams), análise
  de `.lnk`/atalhos, deobfuscação de script em camadas, VBA/p-code em Office, OOXML
  profundo. Amplia o que o `Detection/*` já cobre.
- **B7 (P2, M) — Ativar ETW/AMSI reais** para varredura de script em runtime (hoje
  `IsAvailable=false`). Depende do serviço (ver C5).
- **B8 (P2, M) — Persistência além do básico.** Hoje `PersistenceCollector` cobre os
  vetores comuns; somar IFEO, AppInit_DLLs, COM hijack (CLSID), Winlogon, drivers/serviços
  de boot. Alimenta diretamente a remediação (§C).

---

## C. Eliminação de vírus (remediação)

A engine de remediação já é **madura**: ações reversíveis, gates de
privilégio/confirmação/risco, journal, exclusão pós-reboot (`DataVanger.Engine/Remediation/*`).
Lacunas:

- **C1 (P0, —) — Sem assinaturas, não há eliminação automática.** A base de hashes
  conhecidos (§B1) é o que destrava `ConfirmedMalware` → quarentena automática. Sem ela,
  todo o motor de remediação fica restrito a ação manual. **Pré-requisito de tudo aqui.**
- **C2 (P1, M) — Remediação transacional.** Plano multi-ação atômico: se um passo falha,
  rollback do conjunto (hoje o journal registra, mas não há "tudo-ou-nada"). Reduz estado
  parcial após falha.
- **C3 (P1, M) — Detecção → plano de remediação automático.** Ligar achados de
  persistência/comportamento (§B2/B8) à geração de `RemediationPlan` correspondente
  (matar processo + remover autorun + quarentenar dropper como um caso só).
- **C4 (P1, M) — Remoção em boot/early-launch** para ameaças travadas/persistentes além
  do reboot-pending atual (ex.: fila de remoção executada antes do shell carregar).
- **C5 (P2, G) — Ativar proteção em tempo real (serviço).** Hoje o serviço é stub; ativá-lo
  permite **bloquear na escrita** em vez de só detectar sob demanda — o salto de "scanner
  on-demand" para "AV de proteção contínua". Grande, mas é o diferencial.
- **C6 (P2, M) — Verificação pós-remediação** (já há testes de `PostRemediationVerification`):
  reescanear o alvo e confirmar que a ameaça/persistência sumiu, com relatório.

---

## D. Conserto de erros (falsos positivos + dívidas)

O relatório real tinha **853 SUSPEITO + 232 ALTO RISCO e 0 CRÍTICO**, dominado por apps
legítimos em `AppData` — são "erros" de julgamento concretos (J-2..J-5):

- **D1 (P0, M) — Reduzir o flood de FP em `AppData`.** Estender o conceito de "container
  benigno" (`PathTaxonomy.IsKnownBenignScriptContainer`) para Electron `resources\app`,
  Windows Store `Packages`, pastas por fabricante; e/ou subir `MinScoreToReport` para
  cortar a cauda de score 6. (J-2)
- **D2 (P1, M) — Tratar "assinado válido, publisher não confiável".** Cadeia CA válida é
  exculpatória — dar alívio maior/tier mais silencioso que arquivo sem assinatura. (J-3)
- **D3 (P1, P) — `MZ` embutido não conta como corroboração acionável** em contexto
  assinado/known-app; "Metadados Microsoft fora de caminho comum" suprimido quando o
  arquivo é assinado por publisher confiável. (J-4/J-5)
- **D4 (P1, M) — Endurecer confiança de publisher.** Hoje é *substring* do subject
  (`ThreatClassificationPolicy`/checagem de publisher) — passar para validação de
  cadeia/thumbprint Authenticode. Corrige risco de spoofing e melhora D2.
- **D5 (P2, G) — Decompor god-objects.** `Core/ScanEngine.cs` (~1.332 linhas) em fases
  e `MainWindow.xaml.cs` (~1.077) rumo a MVVM; quebrar o mega-teste
  `LegacyParityTests.cs` em `[Fact]`s focados. Reduz risco de regressão.
- **D6 (P2, P) — Fortalecer o CI recém-criado.** Tornar o check obrigatório para merge,
  somar gate de cobertura e o smoke de "feed de assinatura carrega".

---

## E. Limpeza de lixo (CleanerEngine / JunkCleaningPolicy)

O motor atual é seguro (idade mínima por local, teste real de lock, guarda de caminho
crítico, backup pré-exclusão), mas tem ineficiências e cobertura limitada — pontos
concretos do código (`Core/CleanerEngine.cs`, `Core/JunkCleaningPolicy.cs`):

- **E1 (P1, M) — Eliminar I/O duplicado.** `Measure()` **e** `Clean()` enumeram e chamam
  `IsCleanableFile()` — que **abre cada arquivo com `FileStream(ReadWrite, FileShare.None)`**
  só para medir (`JunkCleaningPolicy.cs:92`, chamado em `Measure` `:118`). Isso é uma
  abertura exclusiva por candidato **na fase de medição**. Adiar o teste de lock para a
  exclusão e reaproveitar a decisão da medição → varredura de lixo bem mais rápida e
  menos intrusiva.
- **E2 (P1, M) — Excluir para a Lixeira (reversível) em vez de copiar+apagar.** Hoje faz
  `File.Copy` para `UserProfile\DataVanger\CleanerBackup` antes de `File.Delete`
  (`CleanerEngine.cs:84,91`) — isso **duplica dados no mesmo disco** (anula o espaço que
  se quer liberar e arrisca encher o disco). Usar `SHFileOperation`/Recycle Bin com
  undo é mais seguro e mais rápido.
- **E3 (P1, P) — Purga/retention dos backups.** O `CleanerBackup` nunca é limpo — vira
  lixo permanente. Adicionar retenção (N dias / tamanho máx) ou descartar via Lixeira.
- **E4 (P2, M) — Ampliar cobertura de lixo.** Lixeira, Prefetch, `Delivery Optimization
  Files`, logs do Windows Update, `Windows.old`, Recent items, cache de DNS/ícones,
  perfis Chrome não-`Default`, Opera GX, Vivaldi, `Code Cache`/`GPUCache` como locais
  explícitos (hoje só pegos por substring se já dentro de um root varrido).
- **E5 (P2, P) — Reaproveitar a medição na limpeza.** `Clean()` re-deriva o `JunkLocation`
  com `GetDefaultLocations().FirstOrDefault` por item (`CleanerEngine.cs:69`); passar a
  decisão já calculada evita reprocessar.
- **E6 (P2, P) — Paralelizar a medição por local** (cada `JunkLocation` é independente).

---

## F. Outras melhorias que identifiquei (além do pedido)

- **F1 (P1, G) — Transporte HTTP de update assinado** (hoje stub que lança) + certificate
  pinning: sem ele não há **como distribuir** as assinaturas de B1. Fecha o ciclo
  detecção→atualização. (Fase 14 do índice de fases do projeto.)
- **F2 (P1, M) — Empacotamento/instalador + serviço Windows real** (hoje `--service` é
  stub): pré-requisito de C5 (realtime) e de uso fora do diretório de build.
- **F3 (P2, M) — Dashboard de status/telemetria na UI** (Module Status UI é "fase futura"):
  mostrar o que está Ativo/Preparado, feed de assinaturas carregado, e progresso por
  estágio (Fase 13).
- **F4 (P2, P) — i18n completo** (en-US é scaffold parcial; categorias de limpeza só pt-BR)
  e acessibilidade (a UI já tem paleta WCAG no `UI_REDESIGN_GUIDE.md`).
- **F5 (P2, P) — Quarantine/restore e scheduler UX** (já há janelas) — fechar pontas de
  experiência (restaurar com verificação, agendamento amigável).

---

## Sequenciamento sugerido (sprints)

1. **Sprint 1 — destravar o núcleo (P0):** B1/C1 (feed de assinaturas + YARA, com aviso),
   D1 (corte do flood de FP), A1 (cache de resultado de detecção). *Resultado:* deixa de
   ser scanner cego, para de gritar em apps legítimos e fica rápido em rescan.
2. **Sprint 2 — profundidade & velocidade (P1):** B2 (ligar memory/behavioral), A2/A3
   (skip de caches + paralelismo adaptativo), A4 (telemetria), E1/E2/E3 (limpeza eficiente
   e segura).
3. **Sprint 3 — eliminação real (P1):** D4 (publisher Authenticode), C2/C3 (remediação
   transacional + auto-plano), B3/B4 (libyara + unpacking).
4. **Sprint 4 — proteção contínua (P2):** F1/F2 (update transport + serviço/instalador),
   C5 (realtime), B7 (ETW/AMSI), D5 (decomposições), E4 (mais lixo), F3 (dashboard).

## Métricas de sucesso

- **Detecção:** > 0 `ConfirmedMalware` em corpus de teste; memory/behavioral produzindo
  evidência no pipeline; libyara real ativa com fallback validado.
- **Velocidade:** Quick < 5 min; Full < 2 h em ~175k arquivos; rescan 50–70% mais rápido
  (cache hits na telemetria); CPU 33%→70%.
- **Falsos positivos:** flood de `AppData` reduzido (cauda de score 6 cortada); apps
  assinados conhecidos não em ALTO RISCO.
- **Eliminação:** plano de remediação automático a partir de achado; verificação
  pós-remediação confirmando limpeza; transacional sem estado parcial.
- **Limpeza:** sem I/O duplicado na medição; exclusão reversível via Lixeira; backups com
  retenção.
- **Qualidade:** CI Windows verde obrigatório; mega-teste decomposto; cobertura medida.

> Tudo preserva o contrato anti-falso-positivo: heurística/comportamento/memória/YARA
> nunca confirmam malware sozinhos; ação automática continua exclusiva de
> `ConfirmedMalware` (hash conhecido ou assinatura confirmada).
