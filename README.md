# Raio-X da Cadeia de Suprimentos

Projeto final do módulo **CY-SE-013** — Paulo Alberto de Oliveira Lima.
Uma app brinquedo (`app/server.js`, um servidor HTTP de 2 linhas) num "antes e depois" de supply chain security. A ideia é o **contraste**, não a quantidade de ferramentas.

```bash
bash run.sh            # reproduz tudo e grava evidencias/ (precisa de docker, opa, conftest, syft, trivy, cosign, jq)
bash run.sh --cleanup  # remove registry local (porta 5050), imagens e cosign.key
```

| Camada | O que foi feito | Arquivos / evidências |
|---|---|---|
| 1. Política | Rego: bloquear root **e** exigir registry aprovado + digest; `opa test` (5/5), `opa eval`, `conftest` | `policy/`, `evidencias/02–04` |
| 2. Inventário | SBOM CycloneDX com Syft (1 comando) + Trivy → **CVE-2021-3177 (CRITICAL) em python2.7 2.7.16-2+deb10u1** na imagem "antes" | `sbom-*.cdx.json`, `evidencias/06–08` |
| 3. Cadeia | Imagem adulterada na mesma tag (Aula 6); Cosign assina o digest e a verificação detecta a troca | `evidencias/09–13`, `.github/workflows/keyless-sign.yml` |
| 4. Compliance | "Que evidência eu teria amanhã?" | `COMPLIANCE.md`, `evidencias/14-manifesto-sha256.txt` |

Mapa de ameaças: [`MAPA_DE_AMEACAS.md`](MAPA_DE_AMEACAS.md).

> **Cosign: keyless × chave de lab.** O enunciado pede **keyless**. No PC, keyless exige login OIDC interativo no navegador, o que quebra um `run.sh` reproduzível; então o `run.sh` usa **chave de laboratório** (`cosign.pub` versionada, `cosign.key` fora do git, sem upload ao Rekor). O **keyless de verdade** está no workflow `keyless-sign.yml`: o GitHub Actions assina com o próprio token OIDC (Fulcio + Rekor), verifica a identidade do workflow e prova que uma imagem adulterada falha.

---

## Roteiro da apresentação (5 min)

### 1. Antes (1 min)
- Mostrar `app/Dockerfile.antes`: `FROM node:14` (tag mutável, Debian 10 sem suporte), sem `USER`.
- `docker run --rm --entrypoint id raio-x:antes -u` → **0 (root)** (`evidencias/05-usuario.txt`).
- Nenhum inventário, nenhuma assinatura: ninguém sabe o que tem dentro nem se é a imagem certa.

### 2. Ataque (1 min)
- Cenário da Aula 6: alguém com acesso ao registry publica outra imagem **na mesma tag `1.0.0`**, com um `server.js` que manda `process.env` (segredos) para fora.
- Quem faz `docker pull app:1.0.0` recebe a imagem maliciosa sem perceber (`evidencias/12-adulteracao.txt`: o digest mudou de `6c695ea3…` para outro).
- A vulnerabilidade conhecida também já está lá: Trivy acha **CVE-2021-3177 (CRITICAL)** na base antiga (`08-vuln-real-print.txt`).

### 3. Depois (2 min)
- **Gate Rego:** `conftest test -p policy app/Dockerfile.antes` → 3 FAIL (root, registry, sem digest); `app/Dockerfile` → passa (`04-*`).
- **Inventário:** `syft … -o cyclonedx-json` → SBOM com 3487 componentes; Trivy: antes 7 CRITICAL / 70 HIGH → depois 1 CRITICAL / 29 HIGH (`07-trivy-contagem.txt`). Ainda há CVEs: agora estão **visíveis**.
- **Cosign:** imagem assinada por digest e com SBOM atestado → `cosign verify` OK (`11-verificacao.json`). Imagem adulterada → `Error: no signatures found` (exit 10). Chave de atacante → não confere (`13-*`).
- Ponto-chave: a imagem adulterada **passa** na policy Rego (mesmo Dockerfile) — só a assinatura detecta. Cada camada pega um ataque diferente.

### 4. Por que importa (1 min)
- **SolarWinds (2020):** o build foi comprometido e a atualização maliciosa saiu **assinada pela própria empresa** para ~18 mil clientes. Lição: assinatura sem identidade/proveniência do build não basta — por isso o keyless liga a assinatura ao **workflow** específico e registra no Rekor.
- **XZ Utils (2024):** o backdoor estava no tarball de release, não no git. Um SBOM confiável responde em minutos "quais imagens têm liblzma 5.6.x?", e verificar o digest assinado impede que um artefato trocado entre em produção.

---

## Estrutura
```
app/Dockerfile.antes   app/Dockerfile   app/server.js
policy/dockerfile.rego policy/dockerfile_test.rego
sbom-antes.cdx.json    sbom-depois.cdx.json   cosign.pub
evidencias/00–14 + run.log
run.sh  MAPA_DE_AMEACAS.md  COMPLIANCE.md
.github/workflows/keyless-sign.yml
```
