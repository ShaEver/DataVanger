# ROADMAP VISUAL E TIMELINE
## DataVanger Performance Optimization Project

**Data Início**: Após análise (hoje: 2026-06-20)  
**Data Alvo de Conclusão**: ~30 dias  
**Branch de Desenvolvimento**: `claude/bold-albattani-7o16j4`

---

## VISUALIZAÇÃO GANTT

```
SEMANA 1: Profiling & Discovery Optimization
├─ FASE 1: Profiling & Telemetry       [████████████] 3 dias  (Jun 20-22)
├─ FASE 2: Target Deduplication        [████████] 2 dias      (Jun 23-24)
└─ CHECKPOINT: Baseline established + 15-20% enumeração reduzida

SEMANA 2: I/O & Cache Foundation
├─ FASE 3: I/O Efficiency              [████████████] 4 dias  (Jun 25-28)
├─ FASE 4: Detection Cache (CRITICAL)  [████████████████] 5 dias (Jun 25-29)
├─ FASE 5: Whitelist Strategy          [████████] 4 dias      (Jun 29-Jul 2)
└─ CHECKPOINT: 45-55% improvement em tempo de scan

SEMANA 3: Paralelismo & Quick Scan
├─ FASE 6: Adaptive Threads            [████████████] 3 dias  (Jul 3-5)
├─ FASE 7: Quick Scan Optimization     [██████████] 2 dias    (Jul 6-7)
├─ FASE 8: Profile Separation          [██████████] 3 dias    (Jul 8-10)
└─ CHECKPOINT: Quick < 5 min; CPU 70%+; Full < 3h

SEMANA 4: Fine-tuning & Safety
├─ FASE 9: Trusted Publishers          [███████████] 2 dias   (Jul 11-12)
├─ FASE 10: Archive Optimization       [███████████] 3 dias   (Jul 13-15)
├─ FASE 11: Cache Skipping             [██████████] 2 dias    (Jul 16-17)
└─ CHECKPOINT: Specialized optimizations active

SEMANA 5: Polish & Validation
├─ FASE 12: Per-Stage Optimization     [████████████] 4 dias  (Jul 18-21)
├─ FASE 13: UI/Logging                 [███████] 2 dias       (Jul 22-23)
├─ FASE 14: Testing & Validation       [████████████████] 4 dias (Jul 24-27)
└─ CHECKPOINT: Testes verdes; regressions = ZERO

SEMANA 6: Documentation
├─ FASE 15: Documentation              [██████████] 2 dias    (Jul 28-29)
└─ FINAL CHECKPOINT: Pronto para merge ✓✓✓
```

---

## TIMELINE DETALHADA POR SEMANA

### SEMANA 1: Estabelecer Baseline (Jun 20-24)

```
SEGUNDA (Jun 20)
├─ [8:00] Revisar documentação existente
├─ [9:00] Checkout branch + build limpo
├─ [10:00] Rodar Full Scan baseline
│         └─ Tempo total, CPU %, memory
├─ [11:00] Iniciar FASE 1
│         └─ Wire DeepScanTelemetry
└─ [14:00] EOM: telemetria básica funcionando

TERÇA (Jun 21)
├─ [8:00] Implementar ScanStageProfiler
├─ [10:00] Dashboard em MainWindow
├─ [11:00] Testar telemetria em Full Scan
└─ [15:00] Documentar baseline em JSON

QUARTA (Jun 22)
├─ [8:00] Finalizar FASE 1 testes
├─ [10:00] Começar FASE 2: Target Dedup
├─ [11:00] Implementar RemoveSubsumedTargets()
└─ [15:00] Teste + benchmark

QUINTA (Jun 23)
├─ [8:00] Finalizar FASE 2
├─ [9:00] Commit + push
├─ [10:00] Benchmark: esperado -20% enumeração
└─ [14:00] Análise de resultados

SEXTA (Jun 24)
├─ [8:00] Review FASE 1-2
├─ [10:00] Preparar documentação
└─ [16:00] EOM: Semana 1 completa ✓
```

### SEMANA 2: Cache Foundation (Jun 25 - Jul 2)

```
SEGUNDA (Jun 25)
├─ [8:00] Iniciar FASE 3: I/O Efficiency
├─ [9:00] Implementar ScanBufferPool
├─ [12:00] Integrar em HashingStage
└─ [16:00] Testes básicos

TERÇA (Jun 26)
├─ [8:00] FASE 3: FileTypeIdentification refactor
├─ [10:00] Buffer pooling integration
├─ [11:00] Teste de alocações (medir GC pressure)
└─ [15:00] Commit FASE 3

QUARTA (Jun 27)
├─ [8:00] Iniciar FASE 4: Detection Cache
├─ [9:00] Implementar DetectionResultCache class
├─ [12:00] Integrar em DetectionPipeline
└─ [16:00] Teste de cache hits

QUINTA (Jun 28)
├─ [8:00] FASE 4: Persistência e invalidação
├─ [10:00] Teste: arquivo modificado invalida cache
├─ [12:00] Teste: malicious hash bypassa cache
└─ [16:00] Commit FASE 4

SEXTA (Jun 29)
├─ [8:00] Iniciar FASE 5: Whitelist Strategy
├─ [9:00] Implementar AutoWhitelistStrategy
├─ [12:00] Integrar em PreFilterStage
└─ [15:00] Teste + análise de impacto

SEGUNDA (Jul 1)
├─ [8:00] FASE 5: Microsoft signed files + installed apps
├─ [10:00] Testes de whitelist correctness
├─ [12:00] Logging de files skipped
└─ [15:00] Commit + benchmark

TERÇA (Jul 2)
├─ [8:00] Review FASE 3-5
├─ [10:00] Benchmark completo de semana 2
│         └─ Esperado: 45-55% redução
└─ [16:00] EOM: Semana 2 completa ✓
```

### SEMANA 3: Performance Core (Jul 3-10)

```
QUARTA (Jul 3)
├─ [8:00] Iniciar FASE 6: Adaptive Threads
├─ [9:00] Implementar AdaptiveThreadPool
├─ [12:00] Listener para CPU/I/O feedback
└─ [16:00] Testes básicos

QUINTA (Jul 4)
├─ [8:00] FASE 6: Integração em DeepScanOrchestrator
├─ [10:00] Teste de adaptação dinâmica
├─ [12:00] Verificar CPU utilization > 70%
└─ [15:00] Commit FASE 6

SEXTA (Jul 5)
├─ [8:00] Iniciar FASE 7: Quick Scan
├─ [9:00] Redefinir Quick Profile targets
├─ [12:00] Reduzir analysis (skip expensive modules)
└─ [15:00] Teste: Quick < 5 min

SEGUNDA (Jul 6)
├─ [8:00] FASE 7: Finalização e testes
├─ [10:00] Second run Quick (cache hit) < 2 min
├─ [12:00] Documento de Quick Scan profile
└─ [15:00] Commit FASE 7

TERÇA (Jul 7)
├─ [8:00] Iniciar FASE 8: Profile Separation
├─ [9:00] Redefinir Full vs Deep escopo
├─ [12:00] Gating inteligente por file type
└─ [16:00] Testes de differentiation

QUARTA (Jul 8)
├─ [8:00] FASE 8: Finalização
├─ [10:00] Full scan < 2 horas com gating
├─ [12:00] Deep scan confirma análise profunda
└─ [15:00] Commit FASE 8

QUINTA (Jul 9)
├─ [8:00] Review FASE 6-8
├─ [10:00] Benchmark: CPU 70%+, Full < 2h
└─ [16:00] EOM: Core performance done ✓

SEXTA (Jul 10)
├─ [8:00] Análise de semana 3
├─ [10:00] Documentar achievements
└─ [16:00] Semana 3 finalizada ✓
```

### SEMANA 4: Fine-tuning (Jul 11-18)

```
SEGUNDA (Jul 11)
├─ [8:00] Iniciar FASE 9: Trusted Publishers
├─ [9:00] Expander TrustedPublisherCache
├─ [12:00] Integrar em PeDetectionModule
└─ [16:00] Testes

TERÇA (Jul 12)
├─ [8:00] FASE 9: Finalização
├─ [10:00] Commit
└─ [12:00] Iniciar FASE 10

QUARTA (Jul 13)
├─ [8:00] FASE 10: SmartArchiveAnalyzer
├─ [9:00] Selective extraction
├─ [12:00] Zip bomb protection
└─ [16:00] Testes

QUINTA (Jul 14)
├─ [8:00] FASE 10: Finalização
├─ [10:00] Commit
└─ [12:00] Iniciar FASE 11

SEXTA (Jul 15)
├─ [8:00] FASE 11: Cache Skipping patterns
├─ [9:00] node_modules, __pycache__, etc
├─ [12:00] Não-silencioso logging
└─ [15:00] Testes

SEGUNDA (Jul 16)
├─ [8:00] FASE 11: Finalização
├─ [10:00] Commit
└─ [12:00] Iniciar FASE 12

TERÇA (Jul 17)
├─ [8:00] FASE 12: Per-Stage Optimization
├─ [9:00] Parallelizar Discovery
├─ [12:00] YARA compilation background
└─ [16:00] Early exit optimization

QUARTA (Jul 18)
├─ [8:00] FASE 12: Finalização
├─ [10:00] Benchmark: +5-10% improvement
├─ [12:00] Commit
└─ [15:00] EOM: Fine-tuning done ✓
```

### SEMANA 5: Polish & QA (Jul 19-27)

```
QUINTA (Jul 19)
├─ [8:00] Iniciar FASE 13: UI/Logging
├─ [9:00] Better progress feedback
├─ [12:00] Telemetria em MainWindow
└─ [16:00] Testes

SEXTA (Jul 20)
├─ [8:00] FASE 13: Finalização
├─ [10:00] Commit
└─ [12:00] Iniciar FASE 14: Testing

SEGUNDA (Jul 21)
├─ [8:00] FASE 14: Run all existing tests
├─ [9:00] AntiFalsePositive, ScanProfile, Detection
├─ [12:00] Verificar ZERO regressions
└─ [16:00] Novo teste de cache invalidation

TERÇA (Jul 22)
├─ [8:00] FASE 14: Novo teste de whitelist
├─ [9:00] Novo teste de target dedup
├─ [12:00] Novo teste de adaptive threads
└─ [16:00] Commit testes

QUARTA (Jul 23)
├─ [8:00] FASE 14: Manual benchmarking
├─ [9:00] SSD vs HDD (se possível)
├─ [12:00] Cold cache vs warm cache
└─ [16:00] Documento de resultados

QUINTA (Jul 24)
├─ [8:00] FASE 14: Finalização
├─ [10:00] Review de todos os tests
├─ [12:00] Tudo GREEN ✓
└─ [15:00] Commit FASE 14

SEXTA (Jul 25)
├─ [8:00] Iniciar FASE 15: Documentation
├─ [9:00] Update DEVELOPER_GUIDE.md
├─ [12:00] Create PERFORMANCE_TUNING_GUIDE.md
└─ [16:00] Update ALTERACOES_BETA.md

SEGUNDA (Jul 26)
├─ [8:00] FASE 15: Code comments
├─ [10:00] Architecture documentation
├─ [12:00] Troubleshooting guide
└─ [16:00] Commit final documentation

TERÇA (Jul 27)
├─ [8:00] FASE 15: Revisão final
├─ [10:00] Checklist completo
├─ [12:00] Branch pronta para merge ✓
└─ [15:00] EOM: Semana 5 completa ✓
```

### SEMANA 6: Wrap-up (Jul 28-29)

```
QUARTA (Jul 28)
├─ [8:00] Review final de todas as 15 fases
├─ [10:00] Benchmark final vs baseline
│         └─ Quick: undefined → <5 min
│         └─ Full: 6h → <2h (3-4x)
│         └─ CPU: 33% → 70%+
├─ [14:00] Documentação final
└─ [16:00] Tudo pronto

QUINTA (Jul 29)
├─ [8:00] Último review + QA
├─ [10:00] Branch merge-ready ✓
├─ [14:00] Post-project analysis
└─ [16:00] Project COMPLETO ✓✓✓
```

---

## MATRIZ DE DEPENDÊNCIAS

```
FASE 1 (Profiling)
    ↓
FASE 2 (Dedup) ← Independente, mas usa telemetria de FASE 1
FASE 3 (I/O)   ← Independente, mas usa telemetria de FASE 1
FASE 4 (Cache) ← DEPENDE DE: FASE 3 (buffer pooling)
FASE 5 (Whitelist) ← DEPENDE DE: FASE 1 (telemetria)
    ↓
FASE 6 (Threads) ← Independente
FASE 7 (Quick) ← DEPENDE DE: FASE 4 (cache)
FASE 8 (Profiles) ← DEPENDE DE: FASE 7 (Quick defined)
    ↓
FASE 9-12 (Fine-tuning) ← Todas independentes entre si
    ↓
FASE 13 (UI) ← DEPENDE DE: Todas anteriores
FASE 14 (Testing) ← DEPENDE DE: Todas anteriores
FASE 15 (Docs) ← DEPENDE DE: Todas anteriores
```

**Critical Path** (caminho crítico):
```
FASE 1 → FASE 4 → FASE 7 → FASE 14 → FASE 15
(Profiling → Cache → Quick → Testing → Docs)
≈ 20 dias críticos
```

---

## MÉTRICAS E CHECKPOINTS

### Checkpoint Semanal

```
SEMANA 1:
├─ [ ] Telemetria funcional
├─ [ ] Baseline documentado
├─ [ ] Dedup reduz 20% enumeração
└─ Status: ✓ (Pronto para SEMANA 2)

SEMANA 2:
├─ [ ] I/O efficiency melhora
├─ [ ] Detection cache hits funcionam
├─ [ ] Whitelist skip ~30% arquivos
├─ [ ] Full scan 45-55% mais rápido
└─ Status: ✓ (Pronto para SEMANA 3)

SEMANA 3:
├─ [ ] CPU utilization 70%+
├─ [ ] Quick scan < 5 min
├─ [ ] Full scan < 3 horas
├─ [ ] Profile separation clara
└─ Status: ✓ (Pronto para SEMANA 4)

SEMANA 4:
├─ [ ] Trusted publisher otimização funciona
├─ [ ] Archive analysis 50% mais rápido
├─ [ ] Cache skipping transparente
├─ [ ] Per-stage optimization +5-10%
└─ Status: ✓ (Pronto para SEMANA 5)

SEMANA 5:
├─ [ ] UI responsiva
├─ [ ] TODOS os testes GREEN ✓
├─ [ ] ZERO regressions
├─ [ ] Manual benchmarking validado
└─ Status: ✓ (Pronto para SEMANA 6)

SEMANA 6:
├─ [ ] Documentação completa
├─ [ ] Branch merge-ready
├─ [ ] Full scan 3-4x mais rápido
├─ [ ] Quick scan viável
└─ Status: ✓ PROJECT COMPLETE
```

---

## RISKS & CONTINGENCY

### Se atrasar em uma FASE (> 50% do tempo estimado)

```
OPÇÃO A: Estender prazo (recomendado)
└─ Adicionar 2-3 dias extras
└─ Melhor qualidade que pressa

OPÇÃO B: Skip fase menos crítica
└─ FASE 9 (Trusted Publisher) → pode skip
└─ FASE 11 (Cache Skipping) → pode skip
└─ Nunca skip FASE 1, 4, 7, 14

OPÇÃO C: Paralelizar se possível
└─ FASE 9-12 podem rodar em paralelo
└─ Se atrasou, paralelizar ultimas fases
```

### Se encontrar regressão (performance piorou)

```
Passo 1: Identifique a FASE que regressou
Passo 2: Reverta o commit da FASE
Passo 3: Root cause analysis
Passo 4: Re-implement com fix
Passo 5: +5% improvement antes de proceder
```

---

## COMUNICAÇÃO & UPDATES

### Daily Standup (5 min)

```
[ ] O que fiz ontem?
[ ] O que faço hoje?
[ ] Algum blocker?
[ ] Alinhar com timeline
```

### Benchmarking Report (fim de cada FASE)

```
FASE X: [Name]
├─ Métrica 1: [Before] → [After] (+X%)
├─ Métrica 2: [Before] → [After] (+X%)
├─ Testes: [GREEN] ✓
├─ Status: [✓ COMPLETA / ⏳ PROGRESSO / ❌ BLOCKER]
└─ Next Phase: [FASE X+1]
```

---

## SUMÁRIO VISUAL (Em Progresso)

```
█████████░ 50% - Profiling + Cache Foundation
├─ [████████] FASE 1: Telemetry
├─ [████████] FASE 2: Dedup  
├─ [████████] FASE 3: I/O
├─ [████████] FASE 4: Cache ⭐ CRITICAL
├─ [████████] FASE 5: Whitelist
├─ [░░░░░░░░] FASE 6: Threads
├─ [░░░░░░░░] FASE 7: Quick ⭐ CRITICAL
├─ [░░░░░░░░] FASE 8: Profiles
...
└─ [░░░░░░░░] FASE 15: Docs

PERFORMANCE GAIN SO FAR:
Quick Scan: undefined → progredindo
Full Scan: 6h → progredindo
CPU: 33% → progredindo
```

---

## FINAL DELIVERABLES

### End of Project (Semana 6)

```
✓ Branch mergeable em master
✓ Testes passam (100% GREEN)
✓ Documentação completa
✓ Performance 3-4x melhorada
✓ Quick Scan < 5 minutos
✓ Full Scan < 2 horas
✓ CPU utilization 70%+
✓ Zero regressions
✓ Anti-FP contract preservado
✓ Knowledge transfer complete
```

---

**Este roadmap é um plano vivo.**  
Ajuste conforme necessário; o importante é alcançar os checkpoints de performance.

