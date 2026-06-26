# Guia de Operação — Feed de Atualização Assinado

Como publicar e consumir um **feed de assinaturas assinado** no DataVanger, por cima da
baseline EICAR embarcada. Isto fecha o ciclo de detecção: além dos hashes/regras locais,
o produto passa a receber atualizações de assinatura **autenticadas criptograficamente**.

> **Pré-requisito:** o pipeline já está pronto no código (F1). Falta apenas a **operação**:
> gerar chaves, montar e assinar o feed, publicar em HTTPS e configurar o cliente.

---

## 1. Modelo de confiança (o que é garantido)

- **Manifesto assinado obrigatório.** Só um `manifest.json` assinado por uma **chave fixada
  (pinned)** é aceito (`SignedManifestVerifier`). Não há "trust on first use".
- **Anti-downgrade.** Um manifesto com `Sequence` menor (ou igual com hash diferente) que o
  já aplicado é rejeitado, por feed (`SignedUpdateService` + state store em disco).
- **HTTPS-only, sem redirects, com limites.** O transporte (`HttpUpdateTransport`) só fala
  `https`, rejeita 3xx (anti-SSRF), limita tamanho/tempo e **falha fechado** (qualquer erro
  preserva o último estado bom).
- **Integridade dos pacotes.** Cada pacote é validado por `SHA-256` e tamanho declarados no
  manifesto antes de ser aplicado.
- **Aplicação isolada.** O conteúdo verificado é projetado em arquivos de feed dedicados
  (`known_malicious_sha256.feed.txt`, `yara_rules/feed__*.yar`) — **nunca** sobrescreve as
  listas do usuário nem a baseline. Há rollback para o último conjunto bom.
- **Nada disso produz veredito de malware.** Update é telemetria/operação.

**O que NÃO é garantido:** *certificate pinning de TLS*. O handshake usa a cadeia de
confiança padrão do SO. A autenticidade do feed vem da **assinatura do manifesto** (chave
fixada), que protege integridade/origem mesmo sem pinning de TLS.

---

## 2. Gerar o par de chaves (offline, máquina controlada)

A **chave privada nunca** deve estar no app, em testes ou em qualquer artefato distribuído.

RSA-PSS (recomendado):

```bash
# Chave privada (PKCS#8) — guarde offline, com segurança
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out feed_private.pem
# Chave pública (SubjectPublicKeyInfo) — esta é a que vai FIXADA no cliente
openssl pkey -in feed_private.pem -pubout -out feed_public.pem
```

ECDSA P-256 (alternativa):

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out feed_private.pem
openssl pkey -in feed_private.pem -pubout -out feed_public.pem
```

Algoritmos aceitos pelo verificador: `RSA-PSS-SHA256` e `ECDsa-P256-SHA256`.

---

## 3. Montar os pacotes do feed

Cada pacote é **dado passivo** (texto), nunca código executável. Tipos relevantes
(`UpdatePackageKind`):

| Kind (no manifesto) | Conteúdo | Onde é aplicado no cliente |
|---|---|---|
| `HashBlacklist` | lista de SHA-256 maliciosos (um por linha; `#`/`;` = comentário) | `Signatures/known_malicious_sha256.feed.txt` |
| `HashAllowlist` | lista de SHA-256 conhecidos-seguros | `Signatures/known_safe_sha256.feed.txt` |
| `YaraRules` | regras `.yar` (texto) | `Signatures/yara_rules/feed__<id>.yar` |

Exemplo `feeds/hash-blacklist.txt`:

```
# Feed de exemplo
275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
<outro sha256...>
```

Calcule o `SHA-256` e o tamanho de cada arquivo de pacote — eles vão no manifesto.

```bash
sha256sum feeds/hash-blacklist.txt   # hex; o cliente compara byte a byte
wc -c     feeds/hash-blacklist.txt   # SizeBytes
```

---

## 4. O manifesto (`manifest.json`)

Forma de fio (PascalCase; enums como string). `Kind` = nome do enum; `Signature.Value` =
assinatura **em base64 do payload canônico** (ver §5):

```json
{
  "SchemaVersion": 1,
  "FeedId": "datavanger-default-feed",
  "Sequence": 1,
  "PublishedUtc": "2026-06-26T00:00:00Z",
  "MinimumSupportedClientVersion": "0.0.0",
  "Packages": [
    {
      "Id": "hash-blacklist",
      "Kind": "HashBlacklist",
      "Version": "2026.06.26.1",
      "Sha256": "<sha256 hex do arquivo do pacote>",
      "SizeBytes": 1234,
      "RelativePath": "feeds/hash-blacklist.txt",
      "Required": true
    }
  ],
  "Signature": { "Algorithm": "RSA-PSS-SHA256", "KeyId": "minha-chave-1", "Value": "" }
}
```

- `Sequence` deve **aumentar** a cada publicação (anti-downgrade).
- `RelativePath` é relativo à pasta do manifesto; **não** pode ser absoluto, conter `..`,
  letra de unidade ou prefixo UNC (validado no cliente).
- `KeyId` deve casar com o id da chave fixada configurada no cliente.

---

## 5. Assinar o manifesto (offline)

**Importante:** a assinatura é sobre o **payload canônico** (`UpdateCanonicalPayloadBuilder`),
não sobre os bytes do JSON. Por isso não basta assinar o `manifest.json` com `openssl`.

Use a implementação de referência do próprio repositório (`UpdateManifestSigner.Sign`), que
constrói o payload canônico e assina com a sua chave privada. Um assinador de produção é um
pequeno utilitário **offline** que referencia `DataVanger.Engine` + `DataVanger.Shared`:

```csharp
// Ferramenta offline (NÃO embarque a chave privada no app).
var manifest = /* monte o UpdateManifest com Packages e Sequence */;
var signed = UpdateManifestSigner.Sign(
    manifest,
    File.ReadAllText("feed_private.pem"),
    SignedManifestVerifier.AlgorithmRsaPss,   // ou AlgorithmEcdsaP256
    "minha-chave-1");                          // KeyId
byte[] bytes = UpdateManifestJson.Serialize(signed);
File.WriteAllBytes("manifest.json", bytes);    // publique este arquivo
```

Isso produz o `manifest.json` final com `Signature.Value` preenchido.

---

## 6. Publicar em HTTPS

Sirva, sob uma mesma origem HTTPS e sob o diretório do manifesto:

```
https://feeds.exemplo.com/datavanger/manifest.json
https://feeds.exemplo.com/datavanger/feeds/hash-blacklist.txt
```

O cliente busca `manifest.json` e, para cada pacote, resolve `RelativePath` **na mesma
origem**. Redirects (3xx) são rejeitados — sirva os arquivos diretamente.

---

## 7. Configurar o cliente (DataVanger)

Edite `%UserProfile%\DataVanger\appsettings.json` (ou os campos na tela de Configurações
avançada). Chaves:

```jsonc
{
  "EnableHttpSignedUpdates": true,
  "SignedUpdateFeedUrl": "https://feeds.exemplo.com/datavanger/manifest.json",
  "SignedUpdatePublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "SignedUpdateKeyId": "minha-chave-1",
  "SignedUpdateAlgorithm": "RSA-PSS-SHA256",
  "SignedUpdateFeedId": "datavanger-default-feed",

  // limites do transporte (têm defaults seguros)
  "SignedUpdateHttpTimeoutSeconds": 30,
  "SignedUpdateMaxManifestSizeKB": 512,
  "SignedUpdateMaxPackageSizeMB": 128
}
```

- Na UI, o **toggle** "Atualizações assinadas via HTTP (opt-in)" (grupo *Atualizações*,
  visibilidade *Developer*) liga/desliga; os campos de texto ficam na tela de Configurações
  avançada e/ou no `appsettings.json` acima.
- Com `EnableHttpSignedUpdates=true` + URL + chave (`PEM` + `KeyId`) preenchidos, o
  DataVanger **prefere o feed assinado**; sem isso, cai no caminho legado (`SignatureUpdateUrl`,
  não assinado) inalterado.

Quando uma atualização é aplicada, os hashes verificados aparecem em
`Signatures\known_malicious_sha256.feed.txt` e passam a valer **na próxima varredura**
(o `SignatureDatabase` une os arquivos `*.feed.txt`). Regras YARA do feed vão para
`Signatures\yara_rules\feed__*.yar`.

---

## 8. Operação contínua

- **Publicar uma atualização:** incremente `Sequence`, atualize os pacotes + seus `Sha256`/
  `SizeBytes`, re-assine, e publique. O cliente aplica na próxima checagem.
- **Rollback:** o cliente mantém o último conjunto bom por feed; uma checagem que falha
  preserva o estado anterior. (API `Rollback()` em `ISignedUpdateService`.)
- **Rotação de chave:** publique com novo `KeyId` e atualize `SignedUpdateKeyId` +
  `SignedUpdatePublicKeyPem` no cliente.

---

## 9. Referências de código

- Composição: `DataVanger.Engine/Updates/SignedUpdates/SignedFeedUpdater.cs`
- Aplicação em disco: `DataVanger.Engine/Updates/SignedUpdates/FileSystemSignatureUpdateSink.cs`
- Transporte HTTPS: `HttpUpdateTransport.cs` · Verificador: `SignedManifestVerifier.cs`
- Glue da UI: `DataVanger/Core/SignedFeedUpdateRunner.cs`
- Leitura no scanner: `DataVanger/Core/SignatureDatabase.cs` (une `*.feed.txt`)
- Testes ponta a ponta: `DataVanger.Tests/SignedFeedUpdaterEndToEndTests.cs`
