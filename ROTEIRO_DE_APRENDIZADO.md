# Projeto Final — Roteiro de Aprendizado: Raio-X da Cadeia de Suprimentos

> Material de estudo do projeto final do CY-SE-013. Exemplos tirados dos arquivos reais desta pasta (`app/`, `policy/`, `run.sh`, `evidencias/`, `.github/workflows/keyless-sign.yml`). Digest assinado: `sha256:6c695ea3…8fef`.

---

## 1) O que você precisa dominar

### 1.1 "Antes e depois" — contraste
O projeto não mede quantas ferramentas você usa, e sim se cada camada **muda o resultado** de um ataque. *No lab:* `Dockerfile.antes` (root, `node:14`, sem digest) × `Dockerfile` (registry aprovado, digest, `USER node`).

### 1.2 Policy as Code com Rego (Aulas 1–3)
Regras `deny` que produzem mensagens quando a entrada viola a política. O conftest converte o Dockerfile em JSON (`conftest parse`) e avalia `data.main.deny`.
*No lab:* `policy/dockerfile.rego` com 4 regras: sem `USER`, `USER root`, registry fora de `docker.io/library/`, imagem sem `@sha256:`.

### 1.3 Testar a política: `opa test`, `opa eval`, `conftest`
- `opa test` → testes unitários (`policy/dockerfile_test.rego`, **5/5 PASS**).
- `opa eval` → avalia a regra contra uma entrada e mostra o resultado (`03-opa-eval.txt`: 3 mensagens no antes, `[]` no depois).
- `conftest test` → o *gate* com exit code (antes exit 1; depois exit 0).

### 1.4 Root em container
Rodar como UID 0 dá ao atacante, numa fuga do processo, privilégios máximos no container e mais chance de escapar. *No lab:* `05-usuario.txt` → antes `0`, depois `1000`.

### 1.5 Registry aprovado e digest
Exigir um prefixo confiável bloqueia typosquatting/registry falso; exigir digest bloqueia tag movida. *No lab:* testes `test_registry_nao_aprovado_negado` e `test_tag_sem_digest_negado`.

### 1.6 SBOM com Syft (Aulas 4–5)
Inventário de tudo que há na imagem, em CycloneDX. *No lab:* `syft IMG -o cyclonedx-json=sbom-depois.cdx.json` → 3487 componentes; o antes tem 21070 (`06-sbom-resumo.txt`).

### 1.7 Scan de vulnerabilidades com Trivy
Cruza pacotes com bases de CVE. Pode ler a imagem (`trivy image`) ou o SBOM (`trivy sbom`). *No lab:* **CVE-2021-3177**, CRITICAL, `python2.7 2.7.16-2+deb10u1` (corrigida em `2.7.16-2+deb10u2`) — estouro de buffer em `PyCArg_repr` (`08-vuln-real.json`). Contagem: antes 7 CRITICAL/70 HIGH; depois 1/29.

### 1.8 Ataque de imagem adulterada (Aula 6)
Quem controla o registry (ou o build) troca o conteúdo mantendo a tag. *No lab:* a tag `1.0.0` passou a apontar para uma imagem que exfiltra `process.env` (`12-adulteracao.txt`).

### 1.9 Assinatura Cosign por digest e verificação (Aula 7)
`cosign sign` assina o digest; `cosign verify` confere a assinatura contra a identidade esperada. *No lab:* verify OK no digest original; tag adulterada → `no signatures found` (exit 10); chave de outro → falha (`13-*`).

### 1.10 Keyless × chave
Keyless: certificado efêmero do Fulcio a partir de um token OIDC, registrado no Rekor; verifica-se `--certificate-oidc-issuer` + `--certificate-identity`. Chave: par local. *No projeto:* o enunciado pede keyless; no PC isso exigiria login interativo, então o `run.sh` usa chave de lab e o keyless real fica no workflow `keyless-sign.yml` (OIDC do GitHub Actions) — documentado no README e no mapa de ameaças.

### 1.11 Atestação de SBOM
SBOM assinado e ligado ao digest (`cosign attest --type cyclonedx`), para que ninguém troque o inventário. *No lab:* "SBOM atestado e verificado".

### 1.12 Evidência e compliance (Aulas 8–9)
Evidência boa é **reprodutível, datada e à prova de edição**. *No lab:* `14-manifesto-sha256.txt` (hash de artefatos e evidências + data + digest), `COMPLIANCE.md`.

---

## 2) O que foi feito, passo a passo

| # | Ação | Evidência |
|---|---|---|
| 1 | Versões das ferramentas (OPA 1.21.2, conftest 0.71.1, Syft 1.54.1, Trivy 0.76.0, Cosign v3.1.3) | `01-ferramentas.txt` |
| 2 | `opa test` 5/5 | `02-opa-test.txt` |
| 3 | `opa eval` nos dois Dockerfiles | `03-opa-eval.txt` |
| 4 | `conftest`: antes BLOQUEADO (3 FAIL), depois aprovado | `04-conftest-*.txt` |
| 5 | Build das imagens; usuário 0 × 1000 | `05-usuario.txt` |
| 6 | SBOM Syft das duas imagens | `06-sbom-resumo.txt`, `sbom-*.cdx.json` |
| 7 | Trivy (SBOM e imagem), contagem por severidade | `07-*` |
| 8 | 1 vulnerabilidade real registrada (CVE-2021-3177) | `08-vuln-real.json`, `08-vuln-real-print.txt` |
| 9 | Registry local (porta 5050), push, digest | `09-imagem.txt` |
| 10 | Assinatura + atestação do SBOM | `10-assinatura.txt` |
| 11 | `cosign verify` do digest | `11-verificacao.json` |
| 12 | **Ataque:** imagem adulterada na mesma tag → Rego passa, Cosign rejeita | `12-adulteracao.txt` |
| 13 | **Negativo:** chave do atacante → rejeitada | `13-chave-de-atacante.txt` |
| 14 | Manifesto SHA-256 de tudo | `14-manifesto-sha256.txt` |
| — | Keyless no CI (GitHub Actions) | `.github/workflows/keyless-sign.yml` |

Resultado: `RESULTADO: SUCESSO`, 9/9 `[OK]` (`00-resumo.txt`).

---

## 3) Por que foi feito

| Controle | Ameaça | Caso real |
|---|---|---|
| Rego (root, registry, digest) | Mudança insegura no Dockerfile, base falsa, tag movida | Typosquatting/dependency confusion (Aula 6) |
| SBOM + Trivy | Não saber o que roda; CVE conhecida ignorada | **XZ Utils** — saber em minutos quais imagens têm liblzma afetada |
| Cosign por digest + identidade | Imagem trocada no registry ou build envenenado | **Codecov** (artefato distribuído alterado); **SolarWinds** (por isso keyless liga a assinatura ao workflow) |
| Manifesto de evidências / Rekor | Não conseguir provar o que aconteceu | **SolarWinds** — sem provenance do build, difícil provar onde entrou |

A lição central do ataque do passo 12: **cada camada pega um ataque diferente** — a policy aprovou a imagem adulterada (o Dockerfile era o mesmo), e só a assinatura a detectou.

---

## 4) O que se esperava que você aprendesse

Checklist do enunciado (binário):
- [x] Escreveu e testou a policy Rego → `02`–`04`.
- [x] Gerou o SBOM → `06`, `sbom-*.cdx.json`.
- [x] Encontrou e registrou 1 vulnerabilidade real → `08` (CVE-2021-3177).
- [x] Assinou/verificou com Cosign → `10`–`13` (+ keyless no CI).
- [x] Conectou com um caso real → README "Por que importa" (SolarWinds, XZ Utils), `COMPLIANCE.md`.

Em uma frase: **política impede o erro conhecido, inventário mostra o risco, assinatura prova a integridade e as evidências contam a história depois.**

---

## 5) Comandos para praticar sozinho

```bash
cd ~/Downloads/ADA/Security/raio-x-cadeia-suprimentos
bash run.sh ; cat evidencias/00-resumo.txt

# Política
opa test policy -v
conftest parse app/Dockerfile.antes | opa eval -f pretty -d policy/dockerfile.rego -I 'data.main.deny'
conftest test -p policy app/Dockerfile.antes app/Dockerfile
# Experimente: troque "USER node" por "USER root" numa cópia e rode o conftest

# Inventário
syft localhost:5050/raio-x/app:1.0.0 -o table | head
trivy sbom --severity CRITICAL sbom-antes.cdx.json | head -30
jq '[.components[]|select(.name|test("python"))|.name+" "+.version]' sbom-antes.cdx.json

# Cadeia
export COSIGN_PASSWORD=lab-raio-x
IMG=$(cut -d= -f2 evidencias/09-imagem.txt)
cosign verify --key cosign.pub --insecure-ignore-tlog "$IMG" | jq '.[0].critical'
cosign tree "$IMG"

bash run.sh --cleanup
```

---

## 6) Autoavaliação (com respostas)

**1. Por que a imagem adulterada passou na policy Rego?**
<details><summary>Resposta</summary>Porque a policy avalia o Dockerfile, e o atacante usou o mesmo Dockerfile mudando só o código. Ela previne configuração insegura, não garante integridade do artefato — isso é papel da assinatura.</details>

**2. Quais as 4 regras `deny` do projeto?**
<details><summary>Resposta</summary>Sem `USER`; `USER` root/0; `FROM` fora de `docker.io/library/`; `FROM` sem `@sha256:`.</details>

**3. Diferença entre `opa test`, `opa eval` e `conftest test`?**
<details><summary>Resposta</summary>`opa test` roda testes unitários da policy; `opa eval` avalia uma consulta contra uma entrada e mostra o resultado; `conftest test` aplica a policy a arquivos e devolve exit code — serve de gate.</details>

**4. Qual vulnerabilidade real foi registrada e por que ela existe?**
<details><summary>Resposta</summary>CVE-2021-3177, CRITICAL, no `python2.7 2.7.16-2+deb10u1` da base `node:14` (Debian 10, fim de vida). Corrigida em `2.7.16-2+deb10u2`.</details>

**5. A imagem "depois" não tem vulnerabilidades?**
<details><summary>Resposta</summary>Tem: 1 CRITICAL e 29 HIGH pelo SBOM. Os controles tornam o risco visível e a atualização explícita (novo digest), não zeram CVEs.</details>

**6. Por que assinar o digest e não a tag?**
<details><summary>Resposta</summary>A tag foi movida no ataque; o digest é imutável. A imagem nova não tinha assinatura → "no signatures found".</details>

**7. Por que o `run.sh` usa chave e não keyless, se o enunciado pede keyless?**
<details><summary>Resposta</summary>Keyless no PC exige login OIDC interativo no navegador, o que impede um script reproduzível. O keyless real foi colocado no GitHub Actions, que tem OIDC nativo (`id-token: write`), e a decisão está documentada no README e no mapa de ameaças.</details>

**8. O que se verifica num keyless?**
<details><summary>Resposta</summary>O issuer (`https://token.actions.githubusercontent.com`) e a identidade (o workflow `keyless-sign.yml` na `main` do repositório), além da inclusão no Rekor.</details>

**9. Para que atestar o SBOM?**
<details><summary>Resposta</summary>Para que o inventário fique assinado e ligado ao digest; numa investigação, você confia que aquele SBOM descreve aquela imagem.</details>

**10. Que evidência você teria se a cadeia fosse atacada amanhã?**
<details><summary>Resposta</summary>Digest aprovado + verificação, SBOM atestado, relatório Trivy datado, resultado da policy, manifesto SHA-256 das evidências e, no keyless, a entrada no Rekor com identidade e horário (`COMPLIANCE.md`).</details>

**11. Como o SolarWinds se conecta ao projeto?**
<details><summary>Resposta</summary>O build foi comprometido e a atualização saiu assinada; assinatura sozinha não bastou. Ligar a assinatura à identidade do workflow (keyless) e manter provenance/log de transparência permite detectar e provar onde a adulteração entrou.</details>
