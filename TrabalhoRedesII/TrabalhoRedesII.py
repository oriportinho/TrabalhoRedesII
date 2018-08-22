import secrets
import json


def CriarChave():
    a = secrets.token_bytes(380)
    arq = open('chave.txt', 'w')
    chave = []

    for i in a:
        chave.append(str(i) + "\n")

    arq.writelines(chave)
    arq.close()



#CriarChave()

eleicao = open('eleicao.json', 'r')

votos = json.load(eleicao)
print(votos)

v = zeros(127, Int)
