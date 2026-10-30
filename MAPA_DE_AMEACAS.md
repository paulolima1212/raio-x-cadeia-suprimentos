# Mapa de ameaças — Raio-X da Cadeia de Suprimentos

```
 SOURCE (repo) ──▶ BUILD (Dockerfile + base) ──▶ DISTRIBUTION (registry) ──▶ DEPLOY/RUN
   [A1]               [A2] [A3]                       [A4]                      [A5]
```

| # | Onde o atacante entra | Exemplo | Controle do projeto | Bloqueia ou evidencia? | Prova |
|---|---|---|---|---|---|
| A1 | Commit/PR muda o Dockerfile (remove `USER`, troca a base) | "só um ajuste rápido" que volta para `FROM node:14` como root | Policy Rego (`policy/dockerfile.rego`) no conftest/CI | **Bloqueia** | `evidencias/04-conftest-antes.txt` (3 violações) |
| A2 | Imagem base de registry não aprovado / typosquat | `FROM evil.registry.io/node` | Rego: prefixo `docker.io/library/` obrigatório | **Bloqueia** | `opa test` → `test_registry_nao_aprovado_negado` |
| A3 | Base com vulnerabilidade conhecida ou tag movida | `node:14` (Debian 10, fim de vida) com CVE-2021-3177 | Digest obrigatório (Rego) + SBOM (Syft) + Trivy | **Evidencia** (inventário mostra o que tem e o que está vulnerável) | `06-sbom-resumo.txt`, `07-*`, `08-vuln-real.json` |
| A4 | Imagem adulterada publicada na mesma tag (cenário da Aula 6, build poisoning / registry comprometido) | `1.0.0` trocada por imagem que exfiltra `process.env` | Cosign: assinatura por digest + verificação de identidade | **Bloqueia no gate / evidencia** | `12-adulteracao.txt` ("no signatures found"); a policy Rego **passa** — só a assinatura pega |
| A5 | Atacante assina com a própria chave | chave diferente | Verificação fixa a identidade (`cosign.pub`; em keyless, issuer + workflow) | **Bloqueia** | `13-chave-de-atacante.txt` |

**Limite honesto:** a imagem "depois" ainda tem CVEs (Trivy: 1 CRITICAL e 29 HIGH via SBOM). Os controles não eliminam vulnerabilidades — tornam-nas **visíveis** e o digest torna a atualização **explícita** (Renovate/Dependabot).

**Keyless × chave de laboratório:** o enunciado pede Cosign **keyless**. No PC (`run.sh`) o keyless exige login OIDC interativo no navegador, impossível num script reproduzível; por isso o `run.sh` usa **chave de laboratório** (`cosign.pub` no repo, `cosign.key` no `.gitignore`, sem Rekor). O keyless real roda no GitHub Actions (`.github/workflows/keyless-sign.yml`): identidade = `https://github.com/paulolima1212/raio-x-cadeia-suprimentos/.github/workflows/keyless-sign.yml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com`, registro público no Rekor.
