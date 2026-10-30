# Compliance — "Se essa cadeia fosse atacada amanhã, que evidência eu teria?"

Eu conseguiria responder **o quê, quando, quem e o que mudou**, porque cada etapa deixa um registro verificável:

1. **O que era legítimo (linha de base).** O digest assinado (`evidencias/09-imagem.txt`) e a verificação (`11-verificacao.json`) dizem exatamente qual imagem foi aprovada. O manifesto `14-manifesto-sha256.txt` guarda o hash de Dockerfile, policy, SBOMs, chave pública e de todas as evidências, com data — se alguém editar uma evidência depois, o hash denuncia.
2. **Quem assinou.** Com chave de lab: só quem tem `cosign.key` gera assinatura que confere com `cosign.pub`. No keyless (CI): o certificado Fulcio grava a identidade do workflow e do commit, e o **Rekor** guarda a entrada com horário em log público e imutável — eu posso provar quando a assinatura foi feita e que ninguém a inventou depois.
3. **O que mudou.** Uma imagem trocada tem outro digest e **nenhuma assinatura** (`12-adulteracao.txt`). Comparando o SBOM atestado (`sbom-depois.cdx.json`, ligado ao digest) com o SBOM da imagem suspeita, vejo quais pacotes/arquivos entraram.
4. **Se a vulnerabilidade era conhecida.** O Trivy (`07-*`, `08-vuln-real.json`) registra que, naquela data, a base `node:14` tinha CVE-2021-3177 (CRITICAL). Isso separa "fomos atacados por algo novo" de "ignoramos um aviso".
5. **Se a política estava em vigor.** `opa test` (5/5) e o conftest (`04-*`) mostram qual regra existia e que o Dockerfile aprovado a cumpria; o histórico do git mostra quem mudou a regra e quando.

**O que ainda faltaria em produção:** logs do registry (quem fez push), logs do CI retidos, admission controller (policy-controller) registrando recusas e provenance SLSA do builder — é a mesma lição do **SolarWinds**: o artefato malicioso saiu *assinado*; sem provenance do build e sem log de transparência, não havia como provar onde a adulteração entrou.
