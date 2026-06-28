# Signatures.default — pacote de detecção embarcado

Pacote base de detecção que acompanha o DataVanger. É **copiado para a saída do
build** (ao lado do executável) e **semeado** no diretório de assinaturas gravável do
usuário na primeira execução, de forma **idempotente e aditiva** (nunca sobrescreve o
que o usuário editou — apenas acrescenta o que falta).

Sem este pacote o scanner roda "cego": sem hash conhecido, ele nunca emite
`ConfirmedMalware` nem quarentena automaticamente.

## Conteúdo

- `known_malicious_sha256.txt` — hashes SHA-256 de malware conhecido (um por linha;
  `#`/`;` iniciam comentário). Hoje embarca **somente** a assinatura do **EICAR**
  (arquivo-teste antivírus padrão, inofensivo), que prova o caminho
  confirmado → quarentena ponta a ponta sem risco de falso positivo.
- `yara_rules/` — pacote inicial **FP-safe** de regras (`.yar`/`.yara`), copiado para
  o pacote do usuário. Hoje embarca `eicar.yar` (regra inequívoca do arquivo-teste
  EICAR), para que o motor YARA carregue **pelo menos uma regra** (`YaraRulesLoaded > 0`)
  e o caminho de match seja exercitado. O antigo medo de "auto-casamento" do motor leve
  (que casa por substring) está resolvido: o DataVanger agora **exclui sua própria pasta
  de assinaturas** (e `Signatures.default`) dos alvos de scan, então regras nunca casam
  com o próprio arquivo. Não é um ruleset de produção — ver "Como estender".

## Destino da semeadura

`%UserProfile%\DataVanger\Signatures\` — feita por
`DataVanger.Core.DefaultSignaturePack.EnsureSeeded`.

## Como estender

Acrescente hashes reais em `known_malicious_sha256.txt` e regras `.yar`/`.yara` em
`yara_rules/`, ou distribua um **feed assinado** por cima desta base: `SignedUpdateService`
verifica o manifesto (ECDSA) + SHA-256 por pacote e `FileSystemSignatureUpdateSink` aplica
`HashBlacklist` → `known_malicious_sha256.feed.txt` e `YaraRules` → `yara_rules/feed__<id>.yar`,
que são carregados na varredura seguinte. O conteúdo de produção (volume de hashes/regras
reais) é responsabilidade do operador/feed — este pacote é só a base FP-safe.
