# DataVanger — Fusão v1.5 + v2

Build resultante da fusão das duas versões. Princípio: **arquitetura da v2, inteligência de detecção da v1.5.**

## Base adotada: v2

Mantido integralmente da v2 por serem objetivamente superiores:

- `ThreatClassificationPolicy` enxuta e auditável — single source of truth. `Models.cs` delega label/cor/ação/classe a ela.
- `ReviewFixWindow` — Central de Ações completa (DataGrid editável, quarentena/whitelist/ignorar por item, abrir local, copiar hash, detalhes).
- Regra de ouro preservada: CRÍTICO só com hash confirmado; heurística forte sem hash nunca passa de ALTO RISCO; quarentena automática limitada a malware conhecido.

## Trazido da v1.5

### 1. Detecção de mascaramento de processo de sistema — `ScanEngine.cs`
A v1.5 detectava um `svchost.exe` (ou `lsass`, `csrss`, `services`, `winlogon`, etc.) rodando fora de `System32`/`SysWOW64` — mascaramento clássico de malware. A v2 pura não pegava isso.

Esse critério **não** voltou como decisor de classe (como era na v1.5). Voltou como **pontuação heurística** dentro de `ComputeHeuristics`: `+7` ao score, marcado em `HasStrongMalwareBehavior` para não ser zerado por filtros de caminho confiável.

Resultado para um `svchost.exe` em `%AppData%`: classificado como **ALTO RISCO**, entra na revisão manual pré-selecionado — detecta sem quarentenar automaticamente sem hash. Detecção rica + classificação auditável.

### 2. Motor de limpeza robusto — `CleanerEngine.cs` + `JunkCleaningPolicy.cs`
Substituem a versão simplificada da v2. Recuperado:

- `MinimumAge` por localização — não apaga arquivos recentes (cache de browser com 7 dias, logs com 14, Package Cache com 30).
- Teste real de lock (`FileStream` com `FileShare.None`) antes de marcar como limpável.
- Backup hierárquico de verdade antes de apagar.
- Whitelist dupla: extensões seguras + caminhos de cache conhecidos.
- Metadados de medição (`OldestLastWrite`, `NewestLastWrite`, `HasFilesInUse`) reexpostos em `CleanerItem`.

### 3. Coluna "Mais recente" — `MainWindow.xaml`
Nova coluna no DataGrid de limpeza, usando o `LastWriteLabel` recuperado: o usuário vê a idade dos arquivos antes de decidir limpar.

## O que foi descartado

- A máquina de estados contextual da v1.5 (`ThreatClassificationContext` + `Classify` com dezenas de booleanos): lógica boa, lugar errado. Critérios viraram score na engine; a classe continua decidida num único ponto.
- O `OnReviewAndFix` em texto da v1.5: substituído pela `ReviewFixWindow` da v2.

## Verificação

Verificação estática feita: enum `ThreatClass` consistente (4 definidos / 4 usados), sem referências órfãs aos tipos antigos, sem tipos duplicados, bindings do XAML resolvem. Compilação final exige Windows + .NET 8 SDK (`Compilar.bat`) — não há ambiente WPF no sandbox de geração.
