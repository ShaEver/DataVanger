# DataVanger Beta — alterações consolidadas

Este documento consolida o histórico anterior de alterações dos arquivos `ALTERACOES_v2_0.md` e `ALTERACOES_v2_1.md` e passa a ser o arquivo principal de acompanhamento das mudanças da fase Beta.

> Manutenção recomendada: a cada nova fase concluída e estabilizada, adicionar uma nova seção no final deste arquivo. Não reescrever entradas antigas sem necessidade.

> Nota de segurança (P0, 2026-07-11): menções históricas abaixo a cache limpo,
> `IsTrustedPath` ou reaproveitamento de assinatura foram substituídas. O runtime
> atual recalcula hash/Authenticode no arquivo atual, trata JSON de cache apenas
> como observação limitada e analisa caminhos de fornecedor no Fast Scan.

---

## Histórico herdado — DataVanger v2.0

Base usada: `DataVanger_merged`.

### Motor de detecção

- Versão atualizada de 1.5 para 2.0.
- Mantida a regra anti-falso-positivo: `CRÍTICO`/malware confirmado só ocorre com hash em blacklist/base conhecida ou regra YARA leve marcada explicitamente como `confirmed = true`.
- Heurísticas fortes continuam como `ALTO RISCO`, exigindo revisão manual.
- Adicionado suporte a regras YARA leves em `%USERPROFILE%\DataVanger\Signatures\yara_rules`.
- Adicionada telemetria de YARA: regras carregadas, arquivos checados e hits.
- Adicionada varredura profunda de compactados ZIP/JAR/WAR/EAR e documentos Office macro-enabled (`.docm`, `.xlsm`, `.pptm`) no perfil `Deep Scan`.
- Adicionada análise de conteúdo de scripts dentro de ZIP/JAR quando o arquivo interno é pequeno.
- Ampliada inspeção de scripts para sinais de `certutil`, `bitsadmin`, `curl`, `wget`, `Invoke-WebRequest`, bypass de política de execução e ofuscação longa.
- Atualização de assinaturas agora aceita arquivos com comentários e separadores simples, além de listas pequenas de hashes.
- O monitor em tempo real passou a observar mais extensões sensíveis, incluindo `.hta`, `.jse`, `.wsf`, `.psm1`, `.sys`, `.zip` e `.jar`.

### Redução de falso positivo

- Whitelist/hash seguro continua tendo prioridade sobre heurística e YARA.
- Arquivos assinados por publishers confiáveis continuam sendo desclassificados quando não houver hash malicioso ou assinatura YARA confirmada.
- Caminhos oficiais/protegidos e containers comuns de app continuam reduzindo heurísticas isoladas.
- Quarentena automática continua limitada a malware conhecido por hash, não a heurística.

### Interface e relatórios

- Títulos, rodapé, diagnóstico e relatório foram atualizados para `DataVanger v2.0`.
- Adicionada coluna `Assinatura` no painel de ameaças e no relatório CSV/HTML.
- Diagnóstico agora mostra pasta de regras YARA, quantidade de regras carregadas e status do scan de compactados.
- Configurações agora incluem ativar/desativar YARA leve, scan profundo de compactados, limite de tamanho YARA e limite de entradas por arquivo compactado.
- Mantida correção de contraste: textos sobre fundo branco usam fonte preta.

### Observação importante

Nenhum antivírus consegue garantir zero falso positivo. Esta versão foi ajustada para não tratar heurística como malware confirmado e para exigir evidência forte antes de classificar como `CRÍTICO`.

---

## Histórico herdado — DataVanger v2.1

### Melhorias aplicadas

- Adicionado agendamento com escolha de data e hora.
- Adicionado modo semanal configurável, com escolha de dia, horário e perfil.
- O agendamento agora pode executar Quick, Standard ou Deep em modo silencioso.
- Varredura silenciosa agora aceita `--profile quick|standard|deep`.
- Varredura profunda reforçada com mais alvos de persistência do Windows.
- Análise de arquivos compactados/documentos Office ampliada:
  - detecção de anexos compactados internos;
  - detecção de relações externas em documentos Office;
  - detecção de indícios de autoexecução/macros;
  - inclusão de `.docx`, `.xlsx`, `.pptx`, `.xlam`, `.xla`, `.hta` e `.chm` no conjunto de análise profunda quando aplicável.
- Mantida a política contra falso positivo: heurística aumenta risco, mas não vira malware confirmado sozinha.

---

## Beta — alterações a partir da nova arquitetura

### Status inicial

- Arquivo criado para substituir o acompanhamento separado em `ALTERACOES_v2_0.md` e `ALTERACOES_v2_1.md`.
- As próximas fases Beta devem ser adicionadas abaixo desta seção, em ordem cronológica.

### Fases Beta já concluídas no roadmap atual

- `00_BASELINE_GUARDRAILS` — baseline Alpha travado como oráculo de regressão.
- `01A_UI_NAVIGATION_SHELL` — shell/navegação inicial da UI.
- `01B_I18N_SCAFFOLD` — estrutura de localização com `pt-BR` como padrão e `en-US` parcial.
- `02A_SERVICE_ACTIVATION_REVIEW` — revisão e endurecimento do ciclo de ativação do serviço.
- `02B_IPC_ACL_SECURITY_GATE` — gate de segurança para IPC/ACL.
- `03A_REMEDIATION_CORE_NO_DESTRUCTIVE_ACTIONS` — núcleo de remediação sem ações destrutivas reais.
- `03B_FILE_AND_QUARANTINE_REMEDIATION` — remediação de arquivos com quarentena antes de exclusão.
- `03C_PROCESS_SERVICE_REGISTRY_TASK_REMEDIATION` — modelos de remediação para processo, serviço, registro, tarefa agendada e inicialização.
- `03D_LOCKED_FILE_REBOOT_AND_VERIFICATION` — estado de reboot requerido, operação pendente, cancelamento, replay idempotente e verificação.
- `04_DETECTION_TO_ACTION_POLICY` — política Detection→Action e `RemediationExecutionGate`.
- `04B_REMEDIATION_IPC_SURFACE` — DTOs compartilhados, superfície IPC de remediação e contexto/consentimento autoritativos do lado do servidor.
- `05_REMOVAL_CENTER_UI` — superfície inicial do Removal Center, com UI/ViewModel testável e estado offline honesto.
- `06_SETTINGS_REDESIGN` — configurações agrupadas, em linguagem simples, com níveis Normal/Avançado/Desenvolvedor e confirmação ao desativar proteção.

### 06_SETTINGS_REDESIGN

- **O que mudou:** nova camada de metadados de configurações (descritiva, sem alterar valores) que agrupa as opções existentes do `AppSettings` em categorias em linguagem simples; novo `SettingsRedesignViewModel` (sem dependência de WPF, testável) com revelação Normal/Avançado/Desenvolvedor; nova janela de configurações dirigida por metadados; e regra de confirmação ao desativar configurações de proteção. O `AppSettings` (esquema/migração/padrões/limiares) permanece inalterado.
- **Impacto visível ao usuário:** o botão de Configurações do shell passa a abrir a janela redesenhada, agrupada e com rótulos pt-BR; um seletor de modo de exibição revela opções avançadas/desenvolvedor; desativar uma proteção exige confirmação explícita (o padrão seguro é "Não"). A janela antiga (plana) permanece no código como alternativa.
- **Impacto de segurança/política:** nenhuma mudança em anti-falso-positivo, limiares de detecção, YARA ou semântica de quarentena; nenhuma ação de remediação foi adicionada. Desativar proteção deixou de ser silencioso; limiares brutos (pontuação) ficam ocultos do modo Normal.
- **Estado:** somente UI e preservando comportamento; já ligado ao shell no processo WPF. Migração de esquema **não** foi necessária (metadados aditivos, nenhuma chave persistida nova). Compilação WPF/XAML e testes automatizados validados em Windows/.NET; fluxos manuais de clique seguem dependentes de validação visual quando a automação desktop estiver disponível.
- **Limitações / acompanhamento:** editores brutos numéricos/texto (limiares, URLs, listas de editores) continuam na janela avançada legada; migração completa das strings por configuração para recursos i18n foi adiada (strings em pt-BR embutidas); editores numéricos no novo painel são um próximo passo.
- **Estabilização:** `dotnet restore`, `dotnet build DataVanger.sln`, suíte completa, `--arch x64` e filtros `~Settings`, `~AntiFalsePositive`, `~Quarantine` executados com sucesso. A inspeção manual automatizada de janela foi bloqueada por falha de acesso da automação desktop; a validação visual/click-through permanece como checklist operacional.

### 07_ONBOARDING_TRAY_INSTALLER_HISTORY (parcial — núcleos testáveis)

- **O que mudou:** (1) **Endurecimento da exportação CSV** — novo utilitário `CsvSafe` (neutraliza injeção de fórmula `= + - @`/TAB/CR + aspas RFC 4180); os três exportadores CSV (`ScanEngine`, `ReportService`, `ForensicReportExporter`) passam a usá-lo. (2) **Store de histórico persistente** (`DataVanger.Shared/History/`) para scan, detecção, remediação, verificação, rollback, atualização e eventos de serviço, com regra de honestidade: uma remediação só é considerada resolvida após um evento de verificação aprovado. (3) **Modelos testáveis (sem WPF)** de onboarding (defaults conservadores; nunca enfraquece proteção; primeira execução por arquivo-marcador, sem mudança de esquema) e de status de bandeja (Protegido/Ação necessária/Proteção reduzida/Atualização/Remediação).
- **Impacto visível ao usuário:** relatórios CSV agora abrem com segurança em planilhas (sem execução de fórmula). Onboarding e bandeja são, neste passo, **modelos**: ainda não há janela de onboarding nem ícone de bandeja com status.
- **Impacto de segurança/política:** injeção de fórmula CSV mitigada (CWE-1236). Nenhuma mudança em anti-falso-positivo, YARA, limiares ou semântica de quarentena. A UI permanece **não-elevada** (sem manifesto de administrador). Onboarding só **liga** proteções, nunca desliga. O round-trip do CSV do scan foi preservado (a coluna SHA256 — hex — não é afetada pela neutralização).
- **Estado:** o **endurecimento CSV está ativo** (aplicado aos exportadores, com testes, incluindo `=`, `+`, `-`, `@`, TAB e CR inicial). História + onboarding + bandeja são **núcleos testáveis (WPF-free)**, ainda **não conectados** a uma janela/host/gravação real (pendente de fiação). Validado em Windows/.NET neste ciclo de estabilização dos núcleos.
- **Limitações / acompanhamento:** janela de onboarding + fiação de primeira execução em `App.xaml.cs`; host de bandeja (NotifyIcon com status persistente, hoje só toast de scan silencioso); UX de registro de serviço (elevação pelo serviço, não pela UI); gravação real do histórico a partir do scan/remediação e integração do journal/resultado nos relatórios; revisão de empacotamento/manifesto.
- **Estabilização:** `dotnet restore`, `dotnet build DataVanger.sln`, suíte completa, `--arch x64` e filtros `~Csv`, `~History`, `~Onboarding`, `~Tray`, `~AntiFalsePositive` e `~Quarantine` executados com sucesso. Permanecem pendentes as jornadas manuais/UI de primeira execução, bandeja persistente e instalador/serviço.

### 07 — conclusão da fiação ao vivo (onboarding/bandeja/histórico/serviço)

- **Já implementado anteriormente (núcleos):** `CsvSafe` (ativo), store de histórico, modelos de onboarding e de status de bandeja (sem WPF, testáveis). Não reescritos.
- **Concluído agora (fiação ao vivo):**
  - **Onboarding de primeira execução** — nova `Views/OnboardingWindow.xaml` ligada em `App.xaml.cs`: aparece **antes** do painel apenas na primeira execução (arquivo-marcador `onboarding.done`, sem mudança de esquema do `AppSettings`). "Aplicar" persiste as opções escolhidas (somente **liga** proteções); "Pular" não muda nada. O marcador é gravado em ambos os casos. i18n via `OnboardingLabels` + recursos pt-BR/en-US.
  - **Bandeja (NotifyIcon) ao vivo** — novo `Services/TrayIconHost` (ícone único, criação à prova de falhas) renderiza o `TrayStatusModel` derivado de estado **real** (`_monitor.IsRunning`, ameaças pendentes em `_lastFindings`, status do serviço); menu apenas abre a UI, mostra o estado do serviço ou sai — **nunca** remedia nem eleva. Status de serviço desconhecido/não instalado/não executando/inacessível/degradado é tratado como **proteção reduzida**, não como "protegido". Atualizado ao concluir scan e ao alternar o monitor; descartado ao fechar.
  - **Histórico ao vivo** — novo `Services/ScanHistoryRecorder` (sem WPF, à prova de exceção) ligado ao fluxo de scan: grava início, conclusão (resumo), detecções relevantes e quarentenas já realizadas pelo scan (incluindo autoquarentena do motor). A quarentena durante o scan é gravada como **feita** (`Succeeded`), **nunca como verificada** (nenhuma verificação ocorre no scan). Falha de gravação **nunca** bloqueia o scan.
  - **UX de registro de serviço** — novo `ServiceRegistrationViewModel` (testável) + item de bandeja/janela: mostra o status honesto e instruções de elevação; **não instala, não eleva**, e a UI não exige administrador.
- **O que está ao vivo:** onboarding (primeira execução), ícone de bandeja com status, gravação de histórico durante scans, e a superfície de estado/registro do serviço — todos ligados no processo WPF.
- **O que continua modelo/limitação:** o histórico ainda não é exibido em uma tela dedicada (a gravação é ao vivo; a visualização e a integração do journal de remediação nos relatórios seguem como acompanhamento); o "iniciar com o Windows" registra apenas a preferência (a entrada de inicialização no SO é passo futuro).
- **Deferido:** **UX de instalador** (motor de instalação real está fora de escopo e proibido); apenas status/instruções foram adicionados via a superfície de registro de serviço.
- **Impacto de segurança/política:** UI permanece **não-elevada**; nenhuma elevação automática; nenhum motor dormente ativado; nenhuma remediação a partir da bandeja; nenhuma mudança em anti-FP/YARA/quarentena/política/IPC/gate ou no transporte de atualização da Fase 08. WPF **não** referencia `DataVanger.Engine`.
- **Estado de validação:** revalidado em Windows/.NET nesta estabilização: `dotnet restore`, `dotnet build DataVanger.sln`, suíte completa, `--arch x64` e filtros `~Csv`, `~History`, `~Onboarding`, `~Tray`, `~Service`, `~Update`, `~AntiFalsePositive` e `~Quarantine` executados com sucesso. Checagem WPF manual por processo confirmou primeira execução com onboarding, fechamento/skip seguro, marcador escrito e reabertura direta do app após onboarding; a automação de cliques/tray ficou limitada pelo helper Windows indisponível, então os menus/janelas restantes foram cobertos por auditoria de código e testes focados.
- **Estado final da Fase 07:** **COMPLETE exceto UX de instalador**. Acompanhamentos: tela dedicada de histórico, integração do journal de remediação nos relatórios, preferência "iniciar com Windows" aplicada por fluxo explícito futuro e UX de instalador quando houver escopo seguro.

### 08_HTTP_SIGNED_UPDATE_TRANSPORT (auditoria + finalização)

- **O que mudou:** auditoria do transporte HTTP de atualização assinada — **já implementado** em
  `DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs` — confirmando que é opt-in, somente HTTPS,
  sem redirects (3xx rejeitado), com limite de tamanho (pré-checagem de `Content-Length` + teto de leitura em
  streaming), timeout por requisição e *fail-closed* (qualquer erro retorna `null`). Correção do comentário
  **desatualizado** da interface `IUpdateTransport` (que afirmava "não há transporte de rede"). Adição dos
  testes obrigatórios que faltavam: **sem auto-atualização do binário do app** (o enum `UpdatePackageKind` não
  possui tipo executável e um manifesto assinado com tipo `Unknown` é rejeitado com `PackageKindRejected`,
  estado preservado) e **regressão do transporte de arquivo** (atualização assinada aplicada via
  `FileUpdateTransport`).
- **Impacto visível ao usuário:** nenhum. O transporte HTTP permanece **desligado por padrão** e **não está
  conectado** ao fluxo de atualização ao vivo.
- **Impacto de segurança/política:** verificação de assinatura e anti-downgrade permanecem **autoritativas** e
  upstream (o transporte apenas busca bytes; nada é aplicado antes da verificação). **Nenhuma mudança de
  comportamento de produção** nesta fase — apenas comentário de documentação + testes. Auto-atualização do
  binário do app é **estruturalmente impossível** (não há tipo de pacote executável; `Unknown` é rejeitado).
  Sem alteração em anti-FP/YARA/quarentena.
- **Estado:** transporte HTTP **implementado e testado**, mas **NÃO conectado** ao caminho de atualização ao
  vivo (o `UpdateCommandHandler` só retorna um snapshot de status; a composição `AppSettings →
  HttpUpdateTransportOptions → SignedUpdateService` é uma camada futura). Validado em Windows/.NET nesta
  estabilização.
- **Limitações / acompanhamento:** fiação da composição (mapear as configurações do usuário para o serviço de
  atualização e ligar o transporte HTTP no `UpdateCommandHandler`/serviço); validação manual da página de
  atualização no Windows (status, "atualizar agora", erros de timeout/oversize, assinatura inválida deixa as
  assinaturas inalteradas).
- **Estabilização:** `dotnet restore`, `dotnet build DataVanger.sln`, suíte completa, `--arch x64`, filtro
  `~Update` e filtro `~SignedUpdate` executados com sucesso.

### 09_LATER_DORMANT_ENGINE_ACTIVATION (planejamento/prontidão — sem ativação)

- **O que mudou:** **nenhuma mudança de código de produção.** Apesar do nome, esta fase é de
  **planejamento/prontidão**, não de ativação. Foram produzidos apenas artefatos de planejamento em
  `outputs/`: um **plano de prontidão dos motores dormentes** (`BETA_09_DORMANT_ENGINE_READINESS_PLAN.md`)
  com inventário dos quatro motores dormentes (correlação comportamental, anti-ransomware/arquivos
  protegidos, scanner de memória e correlação ETW), e **quatro ordens de sub-fase report-only** —
  `09A_BEHAVIORAL_REPORT_ONLY`, `09B_PROTECTED_FILES_REPORT_ONLY`, `09C_MEMORY_REPORT_ONLY` e
  `09D_ETW_CORRELATION_REPORT_ONLY` — cada uma com estrutura de 20 pontos (flag default-off, sink
  report-only, alvo de FP com condição de parada vinculante, corpus/duração de soak, orçamento de
  desempenho com degradação fail-safe e portões de política/remediação adiados).
- **Impacto visível ao usuário:** nenhum. Os quatro motores permanecem **dormentes**; nenhuma flag de
  prontidão foi ligada; nenhuma nova ação de bandeja/modal é dirigida por motor dormente.
- **Impacto de segurança/política:** **nenhuma mudança** em anti-falso-positivo, YARA, classificador,
  quarentena, política ou gate. O framework de flags (`DataVangerSettings`, todas default-off) e o
  `DataVangerSettingsValidator` (que força `AutomaticQuarantineForNonConfirmedMalwareRequested` desligada)
  permanecem intactos. Os tetos anti-FP de cada motor (`MemoryFinding.CanConfirmMalware => false`,
  `score ≤ 6`; arquivos protegidos com teto `ProtectedActivitySuspected`/`High` exigindo ≥3 categorias;
  comportamental forçando `CanConfirmMalware=false`/`High`; ETW/AMSI nunca confirmam sozinhos) seguem
  inalterados. Evidência comportamental/heurística **nunca** vira `ConfirmedMalware`.
- **Estado:** **COMPLETE como planejamento/prontidão.** Nenhum motor dormente foi silenciosamente ativado;
  ativação real fica decomposta em uma sub-fase por motor, report-only primeiro, com soak e condição de
  parada de FP obrigatórios antes de qualquer promoção. As alterações estabilizadas das Fases 07 e 08
  foram preservadas; a Fase 10 **não** foi iniciada.
- **Limitações / acompanhamento:** as sub-fases `09A`–`09D` são ordens **planejadas** (ainda não
  executadas); cada ativação report-only e suas promoções a política/ação são fases futuras explícitas
  com seus próprios portões (soak aprovado, alvo de FP atingido, design de journal/rollback, gate de
  segurança IPC/ACL).
- **Estabilização:** somente documentação; nenhum build/teste alterado. Validação Windows/.NET das
  sub-fases ocorrerá quando cada ordem report-only for implementada (estabilização Codex recomendada
  fortemente nessa etapa).

## Beta 10 — Profiling de desempenho de scan e separação Full/Deep (planejamento/julgamento)

- **Tipo:** ordem de **planejamento/julgamento somente**. Nenhuma otimização foi implementada; nenhum
  motor dormente foi ativado; nenhuma mudança de comportamento de scan, escopo, perfil, threshold,
  anti-falso-positivo, YARA, quarentena, remediação, IPC, atualização assinada ou serviço. **Zero código
  de produção alterado.**
- **Motivação:** um Full Scan real do usuário rodou a ~7,9 arquivos/s (144.645 arquivos em 18.274 s →
  ~6,1 h projetadas para 174.862), com 33% CPU / 569 MB / 4 threads e **0 hashes / 0 YARA leve / 0 regras
  YARA reais compiladas** (fallback leve). Como a carga de assinatura era nula, a lentidão é **estrutural**
  (enumeração, hashing por arquivo, múltiplas aberturas de stream por arquivo, escopo amplo de `C:\`),
  não de correspondência de assinatura.
- **Análise (em `outputs/BETA_10_SCAN_PERFORMANCE_AND_PROFILE_SEPARATION_PLAN.md`):**
  - **Escopo redundante do Full:** Full e Deep recebem alvos **idênticos** — todas as raízes de drives
    fixos (`C:\`) **mais** ~18 pastas aninhadas já contidas em `C:\` (`TargetDiscovery.cs:27-64`). A
    deduplicação é só por string exata (`Distinct(OrdinalIgnoreCase)`, `:99`), **sem subsunção por
    prefixo**, então as subárvores aninhadas de maior volume (AppData, ProgramData, Program Files,
    Downloads) são percorridas/indexadas duas vezes.
  - **Full ≈ Deep:** mesmo escopo e mesmos módulos de detecção; diferem apenas em tetos (profundidade de
    arquivo 6 vs 3, 4 GB vs 1 GB, sem limite de tempo vs 6 h). Full ⊇ Deep em trabalho.
  - **Cache:** existe cache de hash `(path, mtime, size)`; **falta cache de resultado/limpo** — o pipeline
    de detecção re-roda todo arquivo a cada scan.
  - **Paralelismo:** padrão `Clamp(ProcessorCount/2, 2, 6/8)`; o "4 thread(s)" é esse padrão. 33% CPU
    indica gargalo de I/O, não de CPU. Justificado só como padrão conservador, não teto fixo.
  - **Telemetria insuficiente:** sem divisão de tempo por estágio (enumeração/hash/PE/script/archive/
    Office/YARA/persistência), sem hit/miss de cache, sem caminhos/tipos mais lentos. `DeepScanTelemetry`
    tem contadores mas não está conectado ao caminho de scan ao vivo.
- **Julgamento de nome de fase:** Opção A (`09C_…`) rejeitada (`09C` já é `09C_MEMORY_REPORT_ONLY` e o
  namespace `09x` é reservado a motores dormentes report-only); Opção B literal (`10_…`) rejeitada (`10`
  já é `10_APPSETTINGS_SCHEMA_VERSIONING`). **Recomendado: Opção C — fase autônoma
  `BETA_10_SCAN_PERFORMANCE_AND_PROFILE_SEPARATION`** (numeração Beta, `BETA_10` livre).
- **Colocação recomendada:** **ANTES de `09A_BEHAVIORAL_REPORT_ONLY`** (e necessariamente antes de
  `09B_PROTECTED_FILES_REPORT_ONLY`). O Full Scan de ~6 h é um defeito Beta atual e visível ao usuário,
  independente de motores dormentes; a instrumentação de profiling por estágio é ferramenta **fundacional**
  para medir o custo de runtime que `09A` e (especialmente) `09B` vão adicionar. Ordem:
  `BETA_10 → 09A → 09B → 09C/09D → ativação dormente posterior`.
- **Impacto visível ao usuário:** nenhum. **Impacto de segurança/política:** nenhum. Os motores dormentes
  permanecem dormentes; o caminho de veredito segue os nove módulos compostos.
- **Estado:** **COMPLETE como planejamento/julgamento.** Fase de desempenho **recomendada** como
  `BETA_10`, antes de `09A`. Nenhum motor dormente foi ativado; nenhum comportamento de scan foi alterado.
- **Estabilização:** somente documentação; nenhum build/teste alterado (consistente com a entrega de
  planejamento da Beta 09). Estabilização Codex recomendada quando a ordem `BETA_10` for implementada.

## Beta 10 — Implementação: profiling, dedup de alvos, cache de resultado e separação Full/Deep

- **Tipo:** implementação da fase `BETA_10` na ordem solicitada (profiling → medição → dedup/cache/
  separação Full/Deep → testes). Mudanças **aditivas e seguras**; nenhum motor dormente ativado; nenhuma
  mudança em thresholds de detecção, política anti-falso-positivo, YARA, quarentena, remediação, IPC,
  atualização assinada ou serviço.
- **Profiling/medição:** novo `DataVanger/Infrastructure/ScanStageProfiler.cs` (acumulador thread-safe de
  tempo por estágio, baixo overhead). Instrumentados no caminho legado de `ScanEngine`: coleta de
  persistência, coleta de processos, enumeração, hashing e pipeline de detecção. Tempos por estágio são
  expostos em `ScanMetrics.StageSeconds` e impressos na seção “Profiling por estágio (Beta 10)” do
  relatório TXT. Apenas diagnóstico — nunca alimenta o classificador.
- **Deduplicação de alvos:** `TargetDiscovery.RemoveContainedPaths` (subsunção canônica por prefixo, com
  fronteira de separador para não confundir `C:\Users` com `C:\UsersData`) substitui o `Distinct` por
  string exata. Quando `C:\` está presente, as ~18 subpastas aninhadas deixam de ser percorridas/indexadas
  em duplicidade. **Nenhuma cobertura é perdida** — arquivos sob um alvo removido continuam sendo
  enumerados pelo alvo ancestral.
- **Cache de resultado limpo (opt-in, default OFF):** novo `ScanOptions.UseScanResultCache` (false por
  padrão). `Sha256HashService` ganha um fingerprint de assinatura por entrada e `TryCleanSkip`, que só
  reaproveita um veredito quando o arquivo está inalterado (path+mtime+tamanho), foi **known-safe** com
  score 0, e o **fingerprint de assinatura** (carimbo de blacklist/whitelist/pasta de assinaturas+YARA +
  perfil/thresholds) está inalterado. Em acerto incrementa `SkippedCacheClean`. **Nunca** ignora a checagem
  de hash malicioso: qualquer mudança de assinatura invalida o fingerprint e força reanálise completa.
- **Separação Full/Deep:** o perfil **Deep ignora o cache** (reanálise completa, exaustiva); **Full/Standard/
  Quick** são cache-aware quando o opt-in está ligado. Implementado sem tocar em thresholds de detecção nem
  no escopo de alvos.
- **Testes:** novo `DataVanger.Tests/ScanPerformanceTests.cs` (4 fatos): dedup por subsunção / não-subsunção
  de prefixo semelhante; acumulação por estágio do profiler; e o cache limpo seguro (acerto só com
  known-safe inalterado e mesmo fingerprint; falha em fingerprint diferente/vazio, veredito não-limpo e
  conteúdo alterado). Filtros: `~ScanPerformance`, `~TargetDedup`, `~StageProfiler`, `~CleanCache`.
- **Arquivos alterados:** `DataVanger/Infrastructure/ScanStageProfiler.cs` (novo),
  `DataVanger/Engine/TargetDiscovery.cs`, `DataVanger/Infrastructure/Sha256HashService.cs`,
  `DataVanger/Core/Models.cs`, `DataVanger/Core/ScanEngine.cs`,
  `DataVanger.Tests/ScanPerformanceTests.cs` (novo).
- **Validação:** ⚠️ este ambiente Linux **não possui .NET SDK** e a solução é `net8.0-windows`, então
  **não foi possível compilar nem rodar a suíte xUnit aqui**. As mudanças foram revisadas por inspeção e
  são aditivas/desligadas por padrão (cache). **Build/teste no Windows são obrigatórios antes de confiar:**
  `dotnet build DataVanger.sln`; `dotnet test DataVanger.Tests/DataVanger.Tests.csproj`; filtros
  `~ScanPerformance`, `~Scan`, `~Profile`, `~AntiFalsePositive`, `~Quarantine`.
- **Estado:** implementação aditiva concluída e enviada; **validação Windows pendente**. Cache de resultado
  permanece **desligado por padrão** até validação. Nenhum comportamento de detecção/anti-FP foi alterado.

## Beta 11 — Planejamento: redução de ruído heurístico e falsos positivos em arquivos de sistema

- **Tipo:** fase de **planejamento/julgamento somente**. Nenhum código alterado; nenhum motor dormente
  ativado; nenhuma mudança em comportamento de scan, thresholds de detecção, política anti-falso-positivo,
  YARA, quarentena, remediação, IPC, atualização assinada ou serviço.
- **Motivação (relatório Full Scan real, 14/06, 119.298 arquivos):** **6.213 ALTO RISCO** e 4.960 suspeitos,
  com **0 malware confirmado** e **0 assinaturas/YARA carregadas**. Mineração do relatório: **3.910 ALTO
  RISCO em `C:\Windows\WinSxS` + 947 em `C:\Windows\System32` = 4.857 (~78%) são arquivos do Windows**;
  além de **166 binários assinados válidos** ainda em ALTO RISCO (ex.: `claude.exe` assinado
  `CN="Anthropic, PBC"`, Netmarble).
- **Causa-raiz (em `outputs/BETA_11_HEURISTIC_NOISE_AND_SYSTEM_FILE_FP_REDUCTION.md`):**
  - **RC-1 ponto cego de catálogo:** `WinTrust.VerifyFile` usa `WTD_CHOICE_FILE` (só Authenticode embutido),
    nunca catálogos de segurança; DLLs do sistema são assinadas por catálogo → aparecem como "sem
    assinatura".
  - **RC-2:** como ficam "não assinadas", todos os alívios existentes (−6 assinado, publisher confiável,
    reputação −12 trusted-signer) **não disparam**.
  - **RC-3:** alívio de caminho confiável é **skip, não redução**, e é **desligado em Deep/Full**; System32
    nem está na lista — System32/WinSxS não recebem nenhum alívio no Full.
  - **RC-4:** heurísticas de imports PE **sobrepesadas e sem teto** (+4 injeção, +3 rede/exec, +2 DPAPI/API
    dinâmica, +2 correlação a 2 sinais); +9 = ALTO RISCO trivial. Sem gating por assinatura/caminho/trust.
  - **RC-5:** timestamps de build reprodutível lidos como "anômalos".
  - **RC-6:** publisher trust por substring de nome; assinatura válida de publisher não-listado recebe só −6.
  - **RC-7:** tiers somam só `ScoreDelta`; pilha de Low/Medium chega a ALTO RISCO sem nenhum sinal acionável.
  - **Preservar:** clamp de Crítico (heurística nunca vira CRÍTICO), quarentena automática só para
    ConfirmedMalware, alívio de prevalência, gate de persistência, supressão de caminho do HeuristicAnalyzer.
- **Estratégia anti-FP recomendada:** `TrustContext` único por arquivo (assinatura embutida/catálogo,
  signer, nível de trust, caminho de sistema); **atenuação ciente de trust (não supressão)** mantendo sinais
  acionáveis (RWX, entry-point fora de seção, packer, mascaramento); exigir ≥1 corroboração acionável para
  ALTO RISCO em arquivos confiáveis/sistema — **sem** mexer nos números dos thresholds nem no clamp.
- **Sub-fases e ordem recomendada:** `11A CATALOG_SIGNATURE_VERIFICATION` → `11B SYSTEM_PATH_CONTEXT` →
  `11D PUBLISHER_TRUST_HARDENING` → `11C PE_IMPORT_RECALIBRATION` → `11E TIER_ACTIONABLE_SEPARATION` →
  `11F FP_REGRESSION_CORPUS`. Esforço total Médio–Alto (11A e 11C são as âncoras M). 11A é o maior redutor
  isolado (destrava os alívios existentes); 11C (mudança de pesos, maior risco de falso negativo) só depois
  de trust/contexto existirem.
- **Risco principal:** super-correção virando **falso negativo**. Mitigações: alívio só por evidência
  positiva de trust; preservar pesos de mascaramento/RWX/packer/payload; nunca contornar hash malicioso ou
  YARA confirmado; preservar clamp de Crítico; corpus de regressão (11F) garante que a detecção real continua
  disparando.
- **Arquivos alterados:** `outputs/BETA_11_HEURISTIC_NOISE_AND_SYSTEM_FILE_FP_REDUCTION.md` (novo) e este
  changelog (apêndice).
- **Validação:** somente documentação; nenhum build/teste necessário. A implementação de cada sub-fase exige
  build/test no Windows (`net8.0-windows`) com filtros `~AntiFalsePositive`, `~Publisher`, `~Reputation`,
  `~Scan`, `~Pe`/`~Detection`.
- **Estado:** **COMPLETE como planejamento/julgamento.** Comportamento atual é **arquiteturalmente falho para
  arquivos de sistema** (ponto cego de catálogo) e **agressivo demais para binários assinados/ricos em
  imports**. Nenhum motor dormente ativado; nenhum comportamento de scan alterado.

## Beta 11A — Implementação: verificação de assinatura por catálogo (catalog signature)

- **Tipo:** implementação de `BETA_11A_CATALOG_SIGNATURE_VERIFICATION` (autoridade: documento de fase
  enviado). Mudança **aditiva e contida na identidade de assinatura**; nenhuma mudança em thresholds,
  pesos de heurística PE, remediação, quarentena, IPC/serviço/UI/atualização assinada; nenhum motor
  dormente ativado.
- **Problema (causa-raiz dominante da Beta 11):** DLLs do Windows (System32/WinSxS) são assinadas por
  **catálogo de segurança**, mas `WinTrust.VerifyFile` só checava Authenticode **embutido**
  (`WTD_CHOICE_FILE`) → apareciam como "sem assinatura", perdendo todos os alívios de assinado/publisher/
  reputação e indo para ALTO RISCO (~78% do ALTO RISCO eram arquivos de sistema).
- **Implementação:**
  - `DataVanger/Core/WinTrust.cs`: novo modelo `SignatureVerificationResult` + enum `SignatureSource`
    (`Embedded`/`Catalog`/`None`); `VerifySignature` tenta **Authenticode embutido primeiro** (comportamento
    preservado) e, só se falhar, consulta os **catálogos de segurança do Windows**
    (`CryptCATAdminAcquireContext` → `CryptCATAdminCalcHashFromFileHandle` →
    `CryptCATAdminEnumCatalogFromHash` → `CryptCATCatalogInfoFromContext` → `WinVerifyTrust` com
    `WTD_CHOICE_CATALOG`). Assinante extraído do próprio arquivo de catálogo. Confiança só é concedida
    quando o `WinVerifyTrust` de catálogo retorna sucesso; qualquer falta/falha/exceção → **não assinado**
    (nunca fabrica confiança). Todos os handles liberados em `finally`. Guard `OperatingSystem.IsWindows()`.
    Seams de teste internos para orquestração determinística.
  - `DataVanger/Core/ScanEngine.cs`: `GetSigInfo` passa a usar `VerifySignature` e retorna a fonte; o gate
    de confiança incrementa métrica de catálogo. Arquivos assinados por catálogo agora reportam
    `isSigned=true` com assinante (ex.: Microsoft) e **fluem pelos caminhos de alívio existentes** (early-exit
    de publisher confiável; reputação `−12` trusted-signer; alívio `−6` para assinado-não-confiável) —
    `ReputationEngine`/`PublisherIdentity` **não foram alterados**.
  - `DataVanger/Core/Models.cs`: nova métrica `ScanMetrics.CatalogSignatureHits` (auditoria; exibida na
    telemetria TXT).
- **Invariantes preservadas:** Authenticode embutido inalterado; assinatura inválida não vira válida;
  hash malicioso conhecido continua `ConfirmedMalware` (gate exige `!isKnownMalware`); YARA confirmada
  continua `ConfirmedMalware`; clamp de Crítico inalterado; quarentena automática só para
  `ConfirmedMalware`. Confiança de catálogo vem de evidência de catálogo válida, **nunca** de
  caminho/nome de arquivo (nenhum allowlist de System32/WinSxS foi adicionado).
- **Testes:** `DataVanger.Tests/CatalogSignatureTests.cs` (11 fatos) — precedência embutido>catálogo,
  fallback para catálogo, ambos falham→não assinado, probe de catálogo lançando exceção→sem confiança,
  catálogo reportando não-verificado→não assinado, exceção no embutido→sem crash/sem confiança, caminho
  vazio→não assinado, assinante de catálogo Microsoft confiável pelo caminho de publisher existente,
  assinatura sozinha não confia em publisher arbitrário, e smokes de integração guardados para Windows
  (componente do System32 assinado; arquivo temporário não assinado). Filtros `~Signature`, `~Catalog`,
  `~Publisher`, `~AntiFalsePositive`.
- **Validação:** ⚠️ ambiente Linux **sem .NET SDK** e solução `net8.0-windows` → **não compilado/testado
  aqui**. Lógica de orquestração testada por seams; o caminho nativo de catálogo exige **validação no
  Windows** (`dotnet build`/`dotnet test` + ao menos um arquivo de `System32` e um de `WinSxS` reais).
- **Estado:** implementação aditiva concluída e enviada; **validação Windows pendente**. Apenas 11A; nada
  de 11B/11C/11D/11E/11F além do mínimo de plumbing de metadados de assinatura exigido por 11A.

## Beta 11B — Implementação: contexto de caminho de sistema (System32/SysWOW64/WinSxS/Servicing)

- **Tipo:** implementação de `BETA_11B_SYSTEM_PATH_CONTEXT` (autoridade: documento de fase enviado).
  Mudança **aditiva**, de **contexto/relevo de pontuação** (não skip, não allowlist, não imunidade); apenas
  o mínimo de plumbing exigido por 11B. Nenhuma mudança em thresholds, recalibração de PE (11C),
  remediação, quarentena, IPC/serviço/UI; nenhum motor dormente ativado.
- **Objetivo:** rede de segurança após 11A — locais protegidos genuínos do Windows recebem **relevo
  limitado de ruído heurístico** mesmo em Full/Deep, em vez de serem pontuados como arquivos comuns quando
  o contexto de assinatura está incompleto.
- **Taxonomia (`DataVanger/Detection/PathTaxonomy.cs`):** novo `enum SystemPathKind { None, System32,
  SysWOW64, WinSxS, Servicing, OtherProtectedWindows }` e `ClassifySystemPath` (com sobrecarga interna
  relativa ao windir para testes determinísticos). Classificação **canônica** contra o `%WinDir%` real
  (prefixo terminado em separador), rejeitando look-alikes (`C:\Temp\System32`, `Downloads\System32`,
  drive errado). **Locais graváveis dentro do `%WinDir%`** (`temp`, `tasks`, `tracing`, `debug`,
  `system32\tasks`, `system32\spool`, `syswow64\tasks`) → `None` (não recebem relevo).
- **Relevo (`SystemPathRelief`):** limitado (≤ 4; `OtherProtectedWindows` = 2). É **atenuação, não
  imunidade** — um arquivo fortemente corroborado permanece ALTO RISCO; `None`/usuário = 0.
- **Aplicação (`DataVanger/Core/ScanEngine.cs`):** após a pontuação de reputação e **antes do clamp de
  Crítico**, aplica o relevo apenas quando `!isKnownMalware && !hasConfirmedSignature && score > 0`,
  adicionando uma evidência `Info` transparente ("Localização protegida do Windows (...): contexto de
  sistema reduz ruído heurístico"). Roda em **todos os perfis, incluindo Full/Deep** (não é skip de
  indexação; o skip `!deep && IsTrustedPath` existente foi preservado e permanece separado). Nova métrica
  `ScanMetrics.SystemPathContextApplied` (telemetria TXT).
- **Invariantes preservadas:** visibilidade de Full/Deep (arquivos continuam varridos e reportados quando a
  evidência é significativa); hash malicioso conhecido e YARA confirmada continuam `ConfirmedMalware`
  (relevo nunca se aplica a evidência confirmada); clamp de Crítico inalterado; quarentena automática só
  para `ConfirmedMalware`; **detecção de mascaramento (`HeuristicAnalyzer`) intocada** — o `+7` de nome de
  processo de sistema fora de System32/SysWOW64 continua, e o relevo só ocorre para arquivos genuinamente
  dentro de locais de sistema. Sem allowlist; caminho/nome nunca é prova de segurança.
- **Testes:** `DataVanger.Tests/SystemPathContextTests.cs` (13 fatos) — classificação genuína de
  System32/SysWOW64/WinSxS/Servicing/OtherProtected; rejeição de Windows\Temp, subdirs graváveis
  (System32\Tasks, spool, Tasks, tracing) e look-alikes (Temp\System32, Downloads\System32, drive errado);
  relevo limitado (1..4, < limiar de ALTO RISCO) e zero para não-sistema. Filtros `~SystemPath`,
  `~PathTaxonomy`, `~AntiFalsePositive`, `~Detection`.
- **Validação:** ⚠️ ambiente Linux **sem .NET SDK** e solução `net8.0-windows` → **não compilado/testado
  aqui**. Classificação testada de forma OS-independente pela sobrecarga interna; recomenda-se
  `dotnet build`/`dotnet test` no Windows comparando um caminho protegido real contra um look-alike.
- **Estado:** implementação aditiva concluída e enviada; **validação Windows pendente**. Apenas 11B.
  Follow-up: 11D (publisher), 11C (recalibração PE), 11E (separação acionável/informativo), 11F (corpus).

## Beta 11D — Implementação: fortalecimento de confiança de publisher (graduada + anti-spoof)

- **Tipo:** implementação de `BETA_11D_PUBLISHER_TRUST_HARDENING` (autoridade: documento de fase enviado).
  Mudança de **identidade/decisão de confiança**; apenas o mínimo de plumbing exigido. Nenhuma mudança em
  thresholds, recalibração de PE (11C), remediação, quarentena, IPC/serviço/UI; nenhum motor dormente
  ativado.
- **Modelo de confiança graduado (`DataVanger/Core/PublisherIdentity.cs`):** novo
  `enum PublisherTrustLevel { Unsigned, Invalid, Valid, Trusted, TrustedWindowsComponent }` e
  `EvaluatePublisherTrust(SignatureVerificationResult, settings)`. Distingue: sem assinatura; assinatura
  presente mas não verificada (**Invalid** → sem alívio); assinatura válida de signatário não-listado
  (**Valid** → alívio medido de −6); publisher confiável (**Trusted** → alívio forte); componente do Windows
  assinado por catálogo Microsoft (**TrustedWindowsComponent**).
- **Matching anti-spoof (anchored):** novo `MatchesTrustedNameAnchored`/`IsTrustedPublisherName` — um nome
  confiável só casa no **início de um valor de componente RDN** numa fronteira (espaço/vírgula), nunca por
  aparecer em qualquer lugar do subject. Ex.: `CN=Microsoft Corporation` → confiável; `CN=Evil Microsoft
  Corp`, `CN=Microsofty`, `CN=Anthropic-Evil`, `CN=Definitely Not Anthropic` → **não** confiável. Combinado
  com a exigência de **assinatura válida**, um subject forjado sozinho nunca obtém confiança. O
  `IsTrustedByName`/`MatchesTrustedName` legado (substring) foi **preservado** (usado por testes), mas não é
  mais o mecanismo de produção.
- **Integração do signatário de catálogo (11A):** `WinTrust.VerifySignature` agora reporta também
  `SignaturePresentButUnverified` (invalid vs unsigned). `ScanEngine` e `ReputationEngine` passam a decidir
  confiança pelo caminho **anchored**; assinante de catálogo (ex.: Microsoft) alimenta o mesmo modelo →
  `TrustedWindowsComponent`. Métrica `ScanMetrics.TrustedWindowsComponentHits` (telemetria TXT); evidência
  "Assinado por: … [nível]".
- **Lista padrão de publishers (`DataVanger/Core/AppSettings.cs`):** expandida com signatários conhecidos
  (Anthropic, Apple, Realtek, Lenovo, Dell, Hewlett-Packard/HP Inc, ASUSTeK, Logitech, Qualcomm, Citrix) —
  seguro porque o matching é anchored + exige assinatura válida. OpenAI/Wondershare/SweetLabs continuam
  **fora** dos padrões.
- **Invariantes preservadas:** assinatura válida = alívio, **não** prova de segurança; publisher confiável =
  alívio, **não** imunidade (o early-exit segue restrito a `!isKnownMalware && !hasConfirmedSignature`, então
  hash malicioso conhecido e YARA confirmada **sempre** sobrepõem); assinatura inválida não recebe alívio de
  assinatura-válida; clamp de Crítico e quarentena automática só-`ConfirmedMalware` inalterados; **pesos de
  PE não foram tocados** (11C).
- **Testes:** `DataVanger.Tests/PublisherTrustHardeningTests.cs` — matching anchored (teoria), rejeição de
  spoof por substring/pontuação, níveis graduados (unsigned/invalid/valid/trusted/windows-component),
  detecção invalid-vs-unsigned no `WinTrust` (seams), lista padrão (Anthropic incluído, OpenAI fora,
  resistente a spoof), e que publisher confiável **não** resgata hash malicioso nem concede relief a nome
  forjado. Filtros `~Publisher`, `~Reputation`, `~AntiFalsePositive`, `~Signature`.
- **Validação:** ⚠️ ambiente Linux **sem .NET SDK** e solução `net8.0-windows` → **não compilado/testado
  aqui**. Lógica de matching/níveis testada de forma determinística; recomenda-se `dotnet build`/`dotnet
  test` no Windows (filtros `~Publisher`/`~Reputation`/`~AntiFalsePositive`/`~Scan`), com um componente
  Microsoft assinado por catálogo e um app de terceiros assinado embutido.
- **Estado:** implementação concluída e enviada; **validação Windows pendente**. Apenas 11D. Follow-up: 11C
  (recalibração PE), 11E (separação acionável/informativo), 11F (corpus).

## Beta 11C — Implementação: recalibração de imports PE ciente de confiança (alto risco anti-FP)

- **Tipo:** implementação de `BETA_11C_PE_IMPORT_RECALIBRATION` (autoridade: documento de fase enviado).
  Fase **anti-falso-positivo de alto risco**; mudanças contidas em evidência de imports PE e correlação.
  Nenhuma mudança em thresholds de risco, quarentena/remediação, redesenho de publisher (11D) ou de
  taxonomia de caminho (11B); nenhum motor dormente ativado.
- **Estratégia de atenuação (`DataVanger/Detection/PE/PeImportRecalibration.cs`, novo):** classifica a
  evidência PE em *imports comuns* (injeção, API dinâmica, rede+exec, DPAPI, registro/serviços, anti-debug,
  correlação moderada) vs *anomalias severas/estruturais* (RWX, packer, payload MZ embutido, entry-point
  fora de seção, correlação **forte**, entropia executável) — estas **nunca** são tocadas.
  - **Baixa confiança (não assinado/inválido/válido-não-confiável, fora de sistema):** o total de imports
    comuns é **limitado a 8** (`WeakImportCap`), de modo que imports sozinhos não alcançam ALTO RISCO (9).
    Reputação/caminho/severo continuam somando por cima.
  - **Alta confiança (publisher confiável / componente Windows de catálogo / caminho de sistema genuíno do
    11B):** imports comuns (e um timestamp determinístico/futuro, salvo se houver evidência severa) são
    **rebaixados a informativo**.
  - Aplicado **antes** da reputação para que a redução não seja engolida pelo clamp de Crítico (um arquivo
    cujo score alto vem de evidência severa/heurística **não** é super-aliviado). Nunca roda em evidência
    confirmada; nunca dá imunidade; adiciona uma linha de evidência explicativa.
- **Tuning de correlação (`PeCorrelationEngine.cs`):** "Correlação PE **forte**" (High, +4) agora exige ≥1
  sinal **estrutural** (RWX/packer/payload); três sinais somente de imports passam a "moderada" (+2). Não
  perde sinal estrutural (RWX/packer/payload individuais permanecem) e reduz FP em binários ricos em API.
- **Timestamp:** "Timestamp de compilação anômalo" é rebaixado a informativo apenas em contexto
  confiável/sistema e **sem** anomalia severa (builds determinísticos do Windows deixam de pesar).
- **Integração (`DataVanger/Core/ScanEngine.cs`):** recalibração + relevo 11B movidos para **antes** da
  reputação; nova métrica `ScanMetrics.PeImportsAttenuated` (telemetria TXT).
- **Invariantes preservadas:** RWX, packer, payload embutido, entry-point fora de seção, mascaramento e
  correlação forte (estrutural) permanecem acionáveis; executável não assinado em caminho de risco continua
  podendo virar ALTO RISCO (imports limitados + reputação/heurística); hash malicioso conhecido e YARA
  confirmada continuam `ConfirmedMalware` (recalibração não roda em confirmado); clamp de Crítico e
  quarentena automática só-`ConfirmedMalware` inalterados; **nenhum threshold alterado**.
- **Exemplos antes/depois:** DLL System32 com catálogo falho: ~9 (ALTO RISCO) → ~0 (LIMPO) via demote.
  DLL benigna rica em API só-imports (14): ALTO RISCO → SUSPEITO (cap 8). EXE não assinado suspeito no Temp
  (imports 14 + heurística + reputação): permanece ALTO RISCO. Malware empacotado (RWX/packer/forte):
  permanece ALTO RISCO (severo intocado).
- **Testes:** `DataVanger.Tests/PeRecalibrationTests.cs` — cap de baixa confiança preservando RWX; sem cap
  abaixo do limite; demote em sistema/confiável preservando RWX e (com severo) o timestamp; demote de
  timestamp sem severo; forte nunca rebaixado; vazio seguro; e tuning de correlação (3 imports → moderada;
  com estrutural → forte). Filtros `~Pe`, `~Detection`, `~AntiFalsePositive`.
- **Validação:** ⚠️ Linux **sem .NET SDK**, solução `net8.0-windows` → **não compilado/testado aqui**;
  revisado por inspeção (confirmado que `DetectionCoreTests`/correlação não regridem). Exige `dotnet
  build`/`dotnet test` no Windows (filtros `~Pe`/`~Detection`/`~AntiFalsePositive`/`~Scan`) comparando uma
  DLL de sistema confiável, um app assinado rico em API e um executável não assinado suspeito.
- **Estado:** implementação concluída e enviada; **validação Windows pendente**. Apenas 11C. Follow-up:
  11E (separação acionável/informativo), 11F (corpus de regressão FP).

## Beta 11C — estabilização: composição com publisher trust/reputação

- **Tipo:** estabilização de `BETA_11C_PE_IMPORT_RECALIBRATION`, sem reimplementação da fase.
- **Correção:** a recalibração de imports PE agora roda antes do alívio forte de publisher assinado em
  `ScanEngine`, e o alívio `TrustedSigner` de `ReputationEngine` não subtrai pontuação quando a evidência
  remanescente contém anomalia PE severa/estrutural (RWX, packer, payload embutido, entry-point fora de
  seção, correlação PE forte, entropia executável severa). Imports comuns continuam sendo demovidos/zerados
  em contexto confiável/sistema.
- **Motivo:** impedir que 11C + trust/reputação componham como imunidade acidental para PE severo, preservando
  o objetivo original: reduzir ruído de imports sem enfraquecer sinais estruturais.
- **Testes adicionados:** `DataVanger.Tests/PeRecalibrationTests.cs` cobre alívio de publisher confiável com
  imports comuns (continua zerando ruído), PE severo (não zera), e `TrustedSigner` de reputação sem subtração
  sobre evidência PE severa.
- **Invariantes:** nenhum threshold, quarentena, remediação, serviço, IPC, UI, signed-update, redesign de
  publisher trust, redesign de path taxonomy ou motor dormente foi alterado.

## Beta 11E — Implementação: separação de tier acionável (corroboração para ALTO RISCO confiável/sistema)

- **Tipo:** implementação de `BETA_11E_TIER_ACTIONABLE_SEPARATION` sobre a baseline estabilizada do 11C
  (ZIP Codex GPT-5.5, validado no Windows, 567/567). Mudança na **camada de classificação**; nenhuma
  alteração em thresholds numéricos, recalibração PE (11C), publisher (11D), path taxonomy (11B),
  quarentena/remediação; nenhum motor dormente.
- **Preservação do 11C estabilizado:** a recalibração roda antes do early-exit de publisher confiável (que
  segue restrito a `trustedPublisher && !hasActionableEvidence && score == 0`); `ApplySignedPublisherRelief`
  e o relevo de reputação TrustedSigner continuam **sem apagar** evidência PE severa; imports comuns seguem
  limitados/rebaixados; `IsCommonImportEvidence`/`IsSevereStructuralEvidence` reutilizados sem alteração.
- **Modelo de categorias de evidência (`DataVanger/Classification/EvidenceClassification.cs`, novo):**
  `enum EvidenceClass { Informational, Technical, Suspicious, Actionable, Confirmed }` +
  `Classify(Evidence)` + `HasActionableCorroboration(IReadOnlyList<Evidence>)`. O predicado de
  corroboração acionável é **idêntico** ao predicado estabilizado do 11C (confirmável OU PE
  severa/estrutural), garantindo consistência com o relevo já validado.
- **Gate de ALTO RISCO (`ThreatClassificationPolicy.Classify`):** quando `Score >= High`, um arquivo em
  contexto **confiável/sistema** sem sinal acionável corroborante é limitado a **SUSPEITO** (não ALTO
  RISCO). `ConfirmedMalware` (hash malicioso/YARA confirmada) é checado **antes** e nunca é bloqueado pelo
  gate. Thresholds numéricos e clamp de Crítico inalterados; arquivos não assinados/graváveis pelo
  usuário/de caminho suspeito **não** são protegidos (gate só com `TrustedOrSystemContext`).
- **Plumbing (`ScanFinding`, `ScanEngine`):** novos campos `TrustedOrSystemContext` e
  `HasActionableCorroboration` (default false → comportamento numérico legado para qualquer outra origem de
  finding). A engine define `TrustedOrSystemContext = trustedPublisher || systemKind != None` e
  `HasActionableCorroboration` a partir do mesmo predicado acionável já calculado; adiciona uma evidência
  `Info` explicando o tier limitado (sem esconder evidência; arquivo continua reportado como SUSPEITO).
- **Exemplos:** DLL de sistema/assinada com só imports/metadados técnicos (score 12) → **SUSPEITO**
  (gated); com RWX/payload/forte → **ALTO RISCO**; executável não assinado suspeito (score 12) →
  **ALTO RISCO** (não protegido); hash malicioso/YARA confirmada em qualquer contexto → **CRÍTICO**.
- **Testes:** `DataVanger.Tests/TierActionableSeparationTests.cs` — gate (técnico→SUSPEITO; acionável→ALTO
  RISCO; não confiável não-gated; hash/YARA bypass→CRÍTICO; SUSPEITO/LIMPO inalterados; finding padrão
  numérico inalterado), modelo de categorias, e consistência com o predicado estabilizado do ScanEngine.
  Filtros `~AntiFalsePositive`, `~Detection`, `~Classification`, `~Scan`.
- **Validação:** ⚠️ Linux **sem .NET SDK**, solução `net8.0-windows` → **não compilado/testado aqui**;
  revisado por inspeção (campos default-false preservam toda a classificação numérica existente). Exige
  `dotnet build`/`dotnet test` no Windows (filtros `~AntiFalsePositive`/`~Detection`/`~Scan`), inspecionando
  o relatório de um arquivo confiável/sistema abaixo de ALTO RISCO e de um não assinado suspeito ainda em
  ALTO RISCO.
- **Estado:** implementação concluída e enviada; **validação Windows pendente**. Apenas 11E. Follow-up: 11F
  (corpus de regressão FP).

## Beta 11F — Corpus de regressão de falso positivo (acceptance-gating, somente testes)

- **Tipo:** **somente testes/documentação** — nenhuma mudança em lógica de produção, thresholds, detecção,
  quarentena/remediação, IPC, serviço, signed-update ou motor dormente. Finaliza a rede de segurança do
  BETA 11 (11A–11E), travando menos falsos positivos para arquivos confiáveis/sistema/assinados sem
  introduzir falsos negativos para malware confirmado/acionável.
- **Preservação 11C/11E:** o corpus **exercita** (não altera) a recalibração estabilizada do 11C, a ordem
  recalibração→relevo→reputação→clamp, o fato de o relevo de publisher/reputação não apagar evidência PE
  severa, e o gate de corroboração acionável do 11E. `ConfirmedMalware`, clamp de Crítico e quarentena
  automática só-`ConfirmedMalware` são testados explicitamente.
- **Estrutura do corpus (`DataVanger.Tests/Beta11AcceptanceCorpusTests.cs`, novo):** casos ponta-a-ponta
  via um `Compose(...)` que espelha a composição do `ScanEngine.AnalyzeSingleFileAsync` (11A→11E)
  **reutilizando apenas funções de produção** na ordem da engine — nenhuma pontuação reimplementada;
  sintético, determinístico, sem arquivos reais nem rede. Integrações reais cobertas por `[WindowsOnlyFact]`
  (pulam com motivo explícito fora do Windows; executam no Windows).
- **Matriz de aceitação (`outputs/BETA_11F_ACCEPTANCE_MATRIX.md`, novo):** mapeia cada caso exigido (§10)
  e RC-1..RC-7 / 11A-11E a um teste, com colunas FP↓ / guarda-FN / invariante. Cobre: DLL de System32/WinSxS
  assinada por catálogo e app assinado confiável → **não** ALTO RISCO só por imports; assinado-não-confiável
  com relevo mas **sem imunidade**; DLL benigna rica em API → não ALTO RISCO; timestamp determinístico
  contextualizado; relevo confiável **não** apaga PE severa (RWX/payload/entry → continua ALTO RISCO); não
  assinado suspeito em caminho gravável → ainda ALTO RISCO; mascaramento → ao menos SUSPEITO e não gated;
  hash malicioso/YARA confirmada → CRÍTICO mesmo em contexto confiável/sistema; clamp de Crítico; ação
  automática só para `ConfirmedMalware`.
- **Validação:** ⚠️ Linux **sem .NET SDK**, solução `net8.0-windows` → **não compilado/executado aqui**;
  corpus sintético/determinístico que só chama funções de produção. Exige no Windows `dotnet build`/`dotnet
  test` (filtros `~AntiFalsePositive`/`~Pe`/`~Publisher`/`~Reputation`/`~Scan`/`~Detection`), confirmando que
  os testes `[WindowsOnlyFact]` **executam** (não pulam) no host Windows.
- **Lacunas remanescentes:** integração completa via `ScanEngine.RunAsync` sobre um diretório temporário de
  PEs sintéticos; corpus rotulado benigno+malicioso para taxas empíricas de FP/FN (política de fixtures
  aprovada); componente WinSxS assinado por catálogo real além do `kernel32`.
- **Estado:** corpus de regressão completo e enviado; **validação Windows pendente**. Conclui o BETA 11
  (11A→11F).

## Perf — Correção da lentidão de scan (catalog signature) + análise de julgamento

- **Tipo:** correção de desempenho (sem mudança de detecção/threshold/anti-FP/quarentena) + documento de
  análise. Nenhum motor dormente ativado.
- **Causa-raiz da lentidão (regressão do BETA 11A):** a verificação de assinatura por **catálogo** rodava
  **por arquivo sem cache**. Em Standard, `SignatureCheckThreshold = 6`, então quase todo DLL/EXE com alguns
  imports cruzava o gate → `WinTrust.VerifySignature`; sem assinatura embutida, caía em `VerifyViaCatalog`
  que, **por arquivo**, adquiria contexto de catálogo, **relia+hasheava o arquivo inteiro**
  (`CryptCATAdminCalcHashFromFileHandle`) e buscava no catálogo do SO — só para falhar. Como **83% dos
  arquivos estão em `AppData\Local`** (apps de terceiros, nunca assinados por catálogo), a vazão despencava
  ao entrar nessa região densa (≈ meio do scan), em qualquer perfil.
- **Correção:**
  - `DataVanger/Core/WinTrust.cs`: `VerifySignature(path, allowCatalog = true)` — o probe de catálogo só roda
    quando permitido; Authenticode embutido continua checado para todos os arquivos.
  - `DataVanger/Core/ScanEngine.cs`: o gate de assinatura só permite catálogo para **locais de sistema
    genuínos** (`PathTaxonomy.ClassifySystemPath != None`) — elimina o custo de catálogo da maioria
    (AppData/terceiros). Resultados memoizados por `(path,mtime,size)` + fingerprint do catálogo do SO.
  - `DataVanger/Infrastructure/SignatureTrustCache.cs` (novo): cache persistente de resultado de verificação
    (`trust_cache.json`), espelhando `Sha256HashService` — scans repetidos ficam rápidos; qualquer mudança de
    arquivo/fingerprint é miss (nunca concede confiança obsoleta).
  - Métrica `ScanMetrics.TrustCacheHits` (telemetria TXT). Contexto de catálogo continua adquirido por
    chamada (segurança por thread no pool paralelo).
- **Análise de julgamento (em `outputs/STANDARD_SCAN_SLOWDOWN_AND_JUDGMENT_ANALYSIS.md`):** 1.085 achados,
  0 confirmados/0 hash/0 YARA → **scanner cego** (J-1, maior alavanca: carregar feed de assinatura/YARA +
  avisar "0 assinaturas"); enxurrada de FP de apps benignos em AppData (J-2); fornecedores com assinatura
  válida porém não confiáveis (Wondershare 335, ByteDance 79, …) marcados Suspeito/Alto Risco (J-3);
  sinais "acionáveis" (payload MZ, correlação forte) disparando em instaladores/Electron legítimos (J-4);
  "Metadados Microsoft fora de caminho comum" em apps Microsoft do AppData (J-5). J-2..J-5 são afinamentos
  do BETA 11 (sub-fases candidatas).
- **Testes:** `DataVanger.Tests/SignatureTrustCacheTests.cs` — gating de catálogo (skip quando não-sistema;
  embutido preservado); cache hit em inalterado, miss em mudança de fingerprint/conteúdo; round-trip
  persistência/reload.
- **Validação:** ⚠️ Linux **sem .NET SDK**, solução `net8.0-windows` → **não compilado/testado aqui**.
  Exige `dotnet build`/`dotnet test` no Windows (filtros `~Signature`/`~Catalog`/`~Scan`/`~Pe`/
  `~AntiFalsePositive`) e re-rodar um Standard com `AppData\Local` grande (confirmar que a vazão no meio do
  scan não despenca e que o segundo scan é rápido por cache).

## Níveis de scan — escada coerente Quick < Standard < Full < Deep

- **Tipo:** correção da construção dos níveis de profundidade (sem mudar anti-FP/quarentena/threshold de
  risco). Decisão do usuário: a escada canônica é **Quick < Standard < Full < Deep** (Deep = o mais
  completo).
- **Bug observado (4 relatórios reais):** Quick 880, Standard 1103, Deep 1312, **Full 899** — Full ⊊ Deep
  (0 achados exclusivos), Full < Standard apesar de varrer o disco inteiro, e inversão de cobertura
  (`AppData\Local`: Standard 877 > Deep 570 > Full 455). Causa: três eixos desalinhados —
  `MinPreScore` não-monotônico (Standard era o mais estrito: Full=1, Deep=2, Quick=3, Standard=4),
  `SignatureCheckThreshold` baixo no Deep/Full (limpa mais → menos achados), e Deep≡Full em escopo.
- **Correção:**
  - `DataVanger/Engine/ScanProfileRegistry.cs`: `MinPreScore` agora monotônico decrescente
    (Quick=4, Standard=3, Full=2, Deep=1); `SignatureCheckThreshold`/`PersistenceThreshold` monotônicos
    (Quick/Standard=6, Full=5, Deep=4); extensões de navegador agora varridas por **Deep e Full** (antes só
    Full).
  - `DataVanger/Engine/DeepScan/DeepScanProfileSettings.cs`: tetos invertidos para que **Deep** seja o mais
    profundo (maiores limites de archive/arquivo, sem cap de tempo) e **Full** o amplo-otimizado (antes o
    Full tinha tetos maiores que o Deep).
  - Escopo mantido: `Quick ⊆ Standard ⊆ Full = Deep` (Deep e Full compartilham o disco inteiro; diferem só
    na profundidade por-arquivo).
- **Testes:** `ScanProfileTests` atualizado para o novo contrato (monotonicidade de `MinPreScore` e
  `SignatureCheckThreshold`; tetos Deep ≥ Full) + novo `[WindowsOnlyFact]` checando `alvos(Deep)=alvos(Full)`
  e `Quick ⊆ Standard`.
- **Validação:** ⚠️ Linux **sem .NET SDK** → **não compilado/testado aqui**. No Windows: `dotnet build`/
  `dotnet test --filter ~ScanProfile|~DeepScanProfileDerivation|~Scan`. **Re-rodar os 4 níveis** (limpando
  `trust_cache.json`/`hash_cache.json` entre eles) e confirmar a escada: cobertura Quick ≤ Standard ≤ Full,
  Deep ⊇ Full, e `AppData\Local` do Full ≥ Standard (não 455 < 877). A correção de performance do catálogo
  (commit anterior) deve eliminar o truncamento das varreduras de disco inteiro.

## Quick Scan — correção de vazão (paralelismo por perfil)

- **Tipo:** correção de performance (sem mudar anti-FP/quarentena/threshold/score — contagem de threads
  nunca altera veredito). Sintoma relatado: Quick Scan a **~2,8 arquivos/s** e ~33% de CPU numa máquina
  8-core.
- **Causa raiz:** o paralelismo do caminho vivo estava **invertido para o Quick**. O perfil mais leve e
  mais I/O-bound (arquivos pequenos de pastas do usuário, sem expansão de archive/documento/extensão de
  navegador, pre-score mais estrito) recebia o **menor** número de workers de todos:
  - GUI (`MainWindow.xaml.cs`): `Quick => 2` fixo, enquanto Full/Deep/Standard usavam `Clamp(cores/2,2,4)`.
  - CLI/agendado (default do engine em `ScanEngine.cs`): `Clamp(cores/2,2,6)` → também só ~4 no Quick.
  - Como o trabalho por arquivo é dominado por I/O (hashing lê o arquivo inteiro; vários módulos releem o
    conteúdo), 2 threads deixam ~75% dos núcleos ociosos esperando disco.
- **Correção:**
  - `DataVanger/Engine/ScanProfileRegistry.cs`: novo `RecommendedDegreeOfParallelism(profile, cores)`,
    centralizando o paralelismo por perfil. **Quick = `Clamp(cores, 4, 16)`** (recebe o maior número de
    workers, pois é o mais I/O-bound); demais perfis = `Clamp(cores/2, 2, 6)` (mantém o default conservador
    pareado com o `CpuThrottleDelayMs` dos perfis pesados Full/Deep).
  - `DataVanger/MainWindow.xaml.cs` e `DataVanger/Core/ScanEngine.cs`: ambos passam a usar o método único
    (unifica os dois caminhos que antes divergiam; um valor positivo fornecido pelo chamador ainda vence).
- **Impacto esperado:** em 8-core o Quick passa de 2 → 8 workers (~4×), mantendo verdetos idênticos. Deep/
  Full inalterados (continuam moderados de propósito para não saturar a máquina em varreduras longas).
- **Testes:** `ScanProfileTests.RecommendedDegreeOfParallelism_QuickGetsMostWorkers` (Theory 1/2/4/8/16/32)
  — todo perfil ≥ 1 worker, Quick ≥ os demais, e Quick ≥ 8 em máquinas ≥ 8-core (guarda de regressão contra
  o valor antigo fixo em 2).
- **Validação:** ⚠️ Linux **sem .NET SDK**, solução `net8.0-windows` → **não compilado/testado aqui**. No
  Windows: `dotnet build DataVanger.sln -warnaserror` e `dotnet test --filter ~ScanProfile`; depois rodar um
  Quick Scan e confirmar a subida de CPU/vazão (cartão VELOCIDADE) sem mudança no número de achados.

## FASE 3 — eficiência de I/O (buffer pooling + streaming no caminho de hash)

- **Tipo:** otimização de performance (sem mudar anti-FP/quarentena/threshold/score — o algoritmo de hash
  e a lógica das heurísticas permanecem idênticos; apenas a forma de ler bytes do disco muda). Alvo: reduzir
  20–30% da latência de I/O.
- **Causa raiz:** `Sha256HashService.ComputeSha256` é chamado em **todos** os arquivos elegíveis (Fast e
  Deep) e usava `SHA256.ComputeHash(stream)` com buffer interno de 4 KB, sem hint de leitura sequencial e
  com alocação por arquivo — o ponto de I/O mais quente do scan. O padrão ótimo (`StreamHasher`:
  `IncrementalHash` + `ArrayPool` + streaming) já existia, mas só estava ligado ao pipeline DeepScan
  dormente.
- **Correção:**
  - `DataVanger/Infrastructure/Sha256HashService.cs`: reescrito o caminho de cálculo para usar buffer de
    80 KB alugado do `ArrayPool<byte>.Shared`, `IncrementalHash` (streaming, nunca materializa o arquivo) e
    `FileOptions.SequentialScan`. Cache, validação e tratamento de exceção inalterados.
  - `DataVanger/Detection/HeuristicAnalyzer.cs` (somente Deep, pois Heuristic é desligado no Fast pela FASE
    2b): as heurísticas de entropia e de dados anexados ao PE passam a compartilhar **uma única** leitura de
    cabeçalho (4 KB) em buffer alugado do pool, em vez de abrir o arquivo duas vezes; a varredura de ícone
    falso (até 256 KB) agora só roda **após** o regex de extensão dupla (evita o I/O para nomes comuns) e
    também usa buffer do pool + `SequentialScan`. Lógica de offsets do PE preservada, com limites de leitura
    mais precisos para nunca ler além dos bytes efetivamente lidos (segurança com buffer reciclado).
- **Documentação/testes:** `DetectionModuleSet.IsEnabled` ganhou doc XML do contrato de gating (nomes de
  módulo, default-enabled, contrato anti-FP) e novo `DataVanger.Tests/DetectionModuleSetTests.cs` cobrindo
  Fast/Deep, nomes desconhecidos (default true), case-sensitivity e as fábricas `FastOnly()`/`All()`.
- **Impacto esperado:** vazão de hashing de ~12–25 MB/s para ~50–100 MB/s; Full Scan de 6+ h para ~4–5 h
  (se o hash for ~40% do tempo). Fast inalterado em vazão (já rápido pelo gating da FASE 2b). Verdetos
  idênticos.
- **Validação:** ⚠️ Linux **sem .NET SDK**, solução `net8.0-windows` → **não compilado/testado aqui**. No
  Windows: `dotnet build DataVanger.sln -warnaserror` e `dotnet test DataVanger.Tests/DataVanger.Tests.csproj`;
  com `EnableDetailedTelemetry=true`, comparar a vazão do stage `Hashing` (telemetria da FASE 1) antes/depois
  e confirmar que o número de achados não muda.

## FASE 2 (conclusão) — escopo de alvos por `DeepScanLayerConfig`

- **Tipo:** correção de comportamento + conclusão do contrato de customização do Deep Scan (sem mudar
  anti-FP/quarentena/threshold/score). Fecha o teste `ScanProfileTests.
  ScanProfile_TargetScope_FastIsMinimal_DeepIsConfigurable` que estava vermelho.
- **Causa raiz (escopo de alvos):** `TargetDiscovery.ResolveDeepTargets` adicionava `C:\Windows\Temp` na
  camada **User folders**. Com o preset `UserFoldersOnly` (`IncludeSystemAreas=false`,
  `IncludeProgramFiles=false`), o resultado ainda continha um caminho com "Windows", violando o contrato de
  que esse preset fica estritamente dentro do perfil do usuário.
  - **Correção:** `DataVanger/Engine/TargetDiscovery.cs` — `C:\Windows\Temp` movido para a camada **System
    areas** (onde pertence semanticamente). No preset Default (system areas ligado) a cobertura é idêntica;
    no `UserFoldersOnly` ele deixa de ser incluído. Sem perda de cobertura.
- **Gap fechado (camadas de análise):** `ScanEngine.RunAsync` não projetava as camadas de análise do
  `DeepLayerConfig` (`AnalyzeArchives/AnalyzeDocuments/AnalyzeBrowserExtensions`) sobre os flags por-scan que
  os módulos já consultam (`options.ScanArchives/ScanDocuments/ScanBrowserExtensions`). Resultado: o escopo
  de alvos honrava o config, mas a profundidade de análise não.
  - **Correção:** `DataVanger/Core/ScanEngine.cs` — no início de `RunAsync`, quando `options.DeepLayerConfig`
    é fornecido, seus flags de análise são copiados para `options.Scan*`. O gating dos módulos
    (`ArchiveDetectionModule`/`DocumentDetectionModule`/`BrowserExtensionDetectionModule` em `Supports()`)
    passa a honrar a customização Deep sem tocar em cada módulo. O escopo de alvos continua honrado em
    `TargetDiscovery.ResolveTargets`.
- **Impacto esperado:** `UserFoldersOnly`/`FullDisk`/`Default` agora se comportam de forma consistente entre
  escopo de alvos e profundidade de análise. Verdetos idênticos para um mesmo conjunto de alvos.
- **Validação:** no Windows, `dotnet test DataVanger.Tests/DataVanger.Tests.csproj` — esperado 636/636
  (o único vermelho anterior era este teste de escopo).

### Próximas entradas

Adicionar novas alterações estabilizadas aqui.

## FASE 4 — consolidação de leitura dupla PE (eliminar segundo open+parse em Deep)

- **Tipo:** otimização de performance (sem mudar anti-FP/quarentena/threshold/score). O algoritmo de
  decisão permanece idêntico; apenas um arquivo é lido uma única vez em vez de duas. Alvo: reduzir I/O
  na Deep em ~50% para o módulo PE.
- **Causa raiz (descoberto durante exploração):** `PeDetectionModule.Analyze` abria e fazia parse
  completo **duas vezes** por arquivo PE:
  1. `PeAnalyzer.Analyze(path)` — abre, faz parse, executa `PeSectionAnalyzer.Analyze` que computa
     e armazena `section.Entropy` para cada seção em `PeFile.Sections[].Entropy` (com 2 MB cap idêntico).
  2. `AnalyzeEntropyBySectionAsync(path)` — abre **novamente**, faz parse **novamente**, relê cada seção
     (até 2 MB) para recomputar a entropia idêntica, puramente para uma linha descritiva (Score 0). Além
     disso, lia 2 MB de todo o arquivo para computar `perFileEntropy`, que depois era descartado.
  
  Resultado: em cada arquivo PE da Deep, dois opens + dois parses + releitura de cada seção + 2 MB de
  lixo, quase dobrando o I/O do módulo PE.
- **Correção (aditiva, veredicto-idêntico):**
  - `DataVanger/Detection/PE/PeAnalyzer.cs`: novo `AnalyzeWithFile(path)` retorna a tupla
    `(AnalysisResult, PeFile?)` — o parse único com `section.Entropy` já populado. O `Analyze(path)`
    existente passa a delegar para `AnalyzeWithFile(...).Result`.
  - `DataVanger/Detection/PeDetectionModule.cs`: usa a chamada única, constrói o mapa de entropia
    descritivo a partir de `pe.Sections[].Entropy` (valores já computados, zero I/O adicional).
    Deletado `AnalyzeEntropyBySectionAsync` e o const `MaxSectionEntropyBytes` agora redundante. Nova
    função `BuildSectionEntropyMap(PeFile?)` lê `section.Entropy` (idêntica computação, idêntico cap
    2 MB de `PeSectionAnalyzer`).
  - Métodos `ComputeEntropyAnomalies` e `EnrichEvidenceWithSectionEntropy` **inalterados**; reuso de
    valores.
- **Impacto esperado:** vazão PE em Deep sem mudanças (análise idêntica); I/O do módulo PE ~50% menor;
  Full Scan impacto mínimo visível (PE é ~5–10% do total), mas elimina desperdício estrutural.
- **Anti-FP contrato:** evidência de scoring vem do primeiro parse com `includeSignature: true`; os
  números de entropia por seção são bit-idênticos (mesmo `PeEntropyAnalyzer.Calculate`, mesmo range,
  mesmo cap); a linha descritiva permanece `Category="PE"`, `ScoreDelta=0`, `Strength=Info`,
  `CanConfirmMalware=false`. Clamp-de-Crítico e quarentena automática inalterados.
- **Testes:** `DetectionCoreTests.cs` novo bloco verificando `AnalyzeWithFile` retorna `PeFile` com
  `section.Entropy` populado, e `PeDetectionModule` ainda emite o enriquecimento de entropia descritivo
  com `ScoreDelta==0`.
- **Validação:** Windows — `dotnet build` / `dotnet test --filter "~Pe|~Detection"`. Comparar antes/depois
  com Deep Scan em pasta com muitos executáveis e confirmar contagem de achados / evidência por arquivo
  é idêntica; telemetria (FASE 1) do módulo PE mostra menos operações de leitura.
- **Estado:** implementação aditiva completa; **validação Windows pendente**. Nenhum motor dormente
  ativado; nenhuma mudança de comportamento de detecção/anti-FP.
