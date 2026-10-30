# Política do projeto: (1) não rodar como root; (2) só imagens do registry aprovado, pinadas por digest.
package main

import rego.v1

approved_prefix := "docker.io/library/"

# Aceita a entrada do conftest test ([cmds]) e a do conftest parse / testes ([[cmds]])
cmds := array.concat(
	[c | some c in input; is_object(c)],
	[c | some st in input; is_array(st); some c in st],
)

from_images := [cmd.Value[0] | some cmd in cmds; cmd.Cmd == "from"]
users := [cmd.Value[0] | some cmd in cmds; cmd.Cmd == "user"]

deny contains "Container roda como root: falta instrução USER" if count(users) == 0

deny contains msg if {
	last := users[count(users) - 1]
	last in {"root", "0", "0:0", "root:root"}
	msg := sprintf("Container roda como root: USER %s", [last])
}

deny contains msg if {
	some img in from_images
	not startswith(img, approved_prefix)
	msg := sprintf("Imagem fora do registry aprovado (%s): %s", [approved_prefix, img])
}

deny contains msg if {
	some img in from_images
	not contains(img, "@sha256:")
	msg := sprintf("Imagem sem digest (tag mutável): %s", [img])
}
