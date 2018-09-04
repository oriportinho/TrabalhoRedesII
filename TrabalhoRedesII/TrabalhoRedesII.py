import secrets
import json
import random
import socket
import sys
import os
import rsa


def CriarChave():
    a = secrets.token_bytes(380)
    arq = open('chave.txt', 'w')
    chave = []

    for i in a:
        chave.append(str(i) + "\n")

    arq.writelines(chave)
    arq.close()

def encryptXOR(ksim, input):
    b = ksim.split()
    b = list(map(int, b))
    key = []
    for i in b:
        key.append(str(chr(i)))
    output = ""

    for i in range(len(input)):
        xor_num = ord(input[i]) ^ ord(key[i % len(key)])
        output += chr(xor_num)

    return ''.join(output)

def urna(ip, address, tamanho):
    print("Bem vindo as eleiçoes 2018")
    quantVotos = int(input('selecione a quantidade de votantes: '))
    votos = [0, 0, 0, 0, 0]
    os.system('cls' if os.name == 'nt' else 'clear')

    for i in range(quantVotos):
        print("candidato 1")
        print("candidato 2")
        print("candidato 3")
        print("candidato 4")
        voto = int(input('digite o numero do candidato: '))

        if(voto == 1):
            votos[1]+=1
        elif(voto == 2):
            votos[2]+=1
        elif(voto == 3):
            votos[3]+=1
        elif(voto == 4):
            votos[4]+=1
        else:
            votos[0]+=1
        os.system('cls' if os.name == 'nt' else 'clear')
        input('aguardando novo eleitor')
        os.system('cls' if os.name == 'nt' else 'clear')

    print(votos)

    raw_votos = ', '.join(str(x) for x in votos)


    with open('kpub-tse', mode='rb') as privatefile:
        keydata = privatefile.read()
    kpub_tse = rsa.PublicKey.load_pkcs1(keydata)

    m = str(len(raw_votos))
    menssagem = m.encode('utf8')
    criptado = rsa.encrypt(menssagem, kpub_tse)


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (ip, address)
    print('conectado no ip {} porta {}'.format(*server_address))
    sock.connect(server_address)

    try:

        # Send data
        #print('sending {!r}'.format(criptado))
        sock.sendall(criptado)

        # Look for the response
        amount_received = 0
        amount_expected = len(criptado)

        while amount_received < amount_expected:
            data = sock.recv(tamanho)
            amount_received += len(data)

        with open('kpriv-urna', mode='rb') as privatefile:
            keydata = privatefile.read()
        kpriv_urna = rsa.PrivateKey.load_pkcs1(keydata)

        ksim_urna = rsa.decrypt(data, kpriv_urna)
        votos_xor = encryptXOR(ksim_urna, raw_votos)

        votos_xor = votos_xor.encode('utf8')
        votos_xor = rsa.encrypt(votos_xor, kpub_tse)

        sock.sendall(votos_xor)

    finally:
        sock.close()

def tse(ip, address, tamanho):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = (ip, address)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)

    while True:
        # Wait for a connection
        print('aguardando conexão')
        connection, client_address = sock.accept()
        try:
            print('conectado em: ', client_address)

            # Receive the data in small chunks and retransmit it
            while True:
                data = connection.recv(tamanho)
                # print('received {!r}'.format(data))
                if data:
                    with open('kpriv-tse', mode='rb') as privatefile:
                        keydata = privatefile.read()
                    kpriv_tse = rsa.PrivateKey.load_pkcs1(keydata)

                    decriptado = rsa.decrypt(data, kpriv_tse)
                    tamanhoChave = int(decriptado.decode("utf-8"))

                    arq = open('ksim-tse.txt', 'r')
                    ksim_tse = ""
                    ksim_completa = arq.readlines()
                    for i in range(tamanhoChave):
                        ksim_tse += ksim_completa[i]
                    arq.close()

                    with open('kpub-urna', mode='rb') as privatefile:
                        keydata = privatefile.read()
                    kpub_urna = rsa.PublicKey.load_pkcs1(keydata)

                    criptado = rsa.encrypt(ksim_tse.encode(), kpub_urna)
                    connection.sendall(criptado)

                    data = connection.recv(tamanho)
                    votos_xor = rsa.decrypt(data, kpriv_tse)

                    votos_xor = encryptXOR(ksim_tse, votos_xor.decode("utf-8"))
                    print(votos_xor)
                    connection.close()
                    exit()

                else:
                    print('no data from', client_address)
                    break

        finally:
            connection.close()


def main():
    ip = 'localhost'
    address = 12352
    tamanho = 1024
    if(len(sys.argv) > 1):
        if(sys.argv[1] == "urna"):
            urna(ip, address, tamanho)
        elif(sys.argv[1] == "tse"):
            tse(ip, address, tamanho)
        else:
            print("argumentos validos:\nurna (padrao)\ntse")
    else:
        urna(ip, address, tamanho)

main()
