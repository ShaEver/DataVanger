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
- `yara_rules/` (opcional) — `.yar` confirmados a copiar para o pacote do usuário.
  **Vazio por padrão de propósito:** o motor YARA leve casa por substring, então uma
  regra confirmada embarcada poderia "auto-casar" quando sua própria pasta fosse
  escaneada. O caminho por **hash** (arquivo inteiro) não tem esse efeito.

## Destino da semeadura

`%UserProfile%\DataVanger\Signatures\` — feita por
`DataVanger.Core.DefaultSignaturePack.EnsureSeeded`.

## Como estender

Acrescente hashes reais em `known_malicious_sha256.txt`, ou (futuro) distribua um feed
assinado por cima desta base (ver `outputs/ROADMAP_MELHORIAS_SCAN_ELIMINACAO_LIMPEZA.md`,
item F1 — transporte HTTP de update assinado).
