package main

import rego.v1

df(from, user) := [[{"Cmd": "from", "Value": [from]}, {"Cmd": "user", "Value": [user]}]]

ok_img := "docker.io/library/node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0"

test_depois_aprovado if count(deny) == 0 with input as df(ok_img, "node")

test_sem_user_negado if {
	"Container roda como root: falta instrução USER" in deny with input as [[{"Cmd": "from", "Value": [ok_img]}]]
}

test_user_root_negado if count(deny) == 1 with input as df(ok_img, "root")

test_registry_nao_aprovado_negado if {
	some m in deny with input as df("evil.registry.io/node@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0", "node")
	startswith(m, "Imagem fora do registry aprovado")
}

test_tag_sem_digest_negado if {
	some m in deny with input as df("docker.io/library/node:20", "node")
	startswith(m, "Imagem sem digest")
}
