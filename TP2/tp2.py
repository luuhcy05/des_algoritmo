#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time

# Tabela S-Box usada para substituição de nibbles
SBOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

# Transforma uma string para bits (ASCII para binário)
def string_em_bits(text):
    bits_final = ''
    for char in text:
        #ord transforma string em ascii
        valor_em_ascii = ord(char)
        ascii_em_binario = bin(valor_em_ascii)[2:]  # Remove o prefixo '0b'

        #Coloca 0s para manter 8 bits se houver menos
        while len(ascii_em_binario) < 8:
            ascii_em_binario = '0' + ascii_em_binario

        bits_final += ascii_em_binario
    return bits_final

# Divide bits em grupos de 4 (nibbles)
def definicao_nibbles(bits):
    lista_nibbles = []
    i = 0
    while i < len(bits):
        nibble_string = bits[i:i+4]  # Pega 4 bits
        nibble_string_em_inteiro = int(nibble_string, 2)  # Converte de binário para inteiro
        lista_nibbles.append(nibble_string_em_inteiro)
        i = i + 4

    if (len(lista_nibbles) < 4):
        i = len(lista_nibbles)
        while i < 4:
            lista_nibbles.append(0)
            i += 1
    return lista_nibbles

# Converte lista de nibbles em matriz 2x2
def nibbles_em_matriz(nibble):
    matriz = [[nibble[0],nibble[1]],[nibble[2],nibble[3]]]
    return matriz

# Converte matriz 2x2 em lista de nibbles
def matriz_em_nibbles(matriz):
   nibbles = [matriz[0][0],matriz[0][1],matriz[1][0],matriz[1][1],]
   return nibbles

# XOR entre mensagem e chave
def add_round_key(matriz_mensagem, matriz_chave):
    round = [
        [matriz_mensagem[0][0] ^ matriz_chave[0][0], matriz_mensagem[0][1] ^ matriz_chave[0][1]],
        [matriz_mensagem[1][0] ^ matriz_chave[1][0], matriz_mensagem[1][1] ^ matriz_chave[1][1]]
    ]
    return round

# Substituição de nibbles via SBOX
def sub_nibbles(matriz):
    novos_nibbles = [
        [SBOX[matriz[0][0]], SBOX[matriz[0][1]]],
        [SBOX[matriz[1][0]], SBOX[matriz[1][1]]]
    ]
    return novos_nibbles

# Inversão da segunda linha
def shift_rows(state):
    matriz_invertida = [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]]
    ]
    return matriz_invertida

# Multiplicação no campo finito GF(2^4)
def multiplicacao_campo_finito(num1, num2):
    resultado = 0
    for i in range(4):
        # Verifica se o bit menos significativo de num2 é 1
        if num2 & 1:
            # Xor do acumulador com num1
            resultado ^= num1

        # Verifica se o bit mais alto do num1 está ligado. Para evitar transbordar
        carry = num1 & 0x8

        # Move os bits do num1 para a esquerda (Multiplica por 2)
        num1 <<= 1

        if carry:
            # Reduz pelo polinômio irreducível
            num1 ^= 0x13

        # Remove bits fora dos 4
        num1 &= 0xF

        # Move 1 bit para a direita de num2
        num2 >>= 1

    return resultado

# Operação MixColumns
def mix_columns(nibbles):
    n1, n2 = nibbles[0]
    n3, n4 = nibbles[1]

    nibbles_campo_finito = [[multiplicacao_campo_finito(n1, 1) ^ multiplicacao_campo_finito(n3, 4), multiplicacao_campo_finito(n2, 1) ^ multiplicacao_campo_finito (n4, 4)],
    [multiplicacao_campo_finito(n1, 4) ^ multiplicacao_campo_finito(n3, 1), multiplicacao_campo_finito(n2, 4) ^ multiplicacao_campo_finito(n4, 1)]]

    return nibbles_campo_finito

# Expansão da chave de 16 bits
def key_expansion(nibbles_chave):
    w = [nibbles_chave[0], nibbles_chave[1], nibbles_chave[2], nibbles_chave[3]]

    rcon = [0x8, 0x3]  # Constantes de round

    # w4 e w5
    t = [SBOX[w[3]] ^ rcon[0], SBOX[w[2]]]
    w4 = w[0] ^ t[0]
    w5 = w[1] ^ t[1]

    # w6 e w7
    w6 = w[2] ^ w4
    w7 = w[3] ^ w5

    # w8 e w9
    t = [SBOX[w7] ^ rcon[1], SBOX[w6]]
    w8 = w4 ^ t[0]
    w9 = w5 ^ t[1]

    # w10 e w11
    w10 = w6 ^ w8
    w11 = w7 ^ w9

    round_keys = [
        nibbles_em_matriz([w[0], w[1], w[2], w[3]]),
        nibbles_em_matriz([w4, w5, w6, w7]),
        nibbles_em_matriz([w8, w9, w10, w11])
    ]

    return round_keys

# Representação em hexadecimal
def matriz_em_hex(matriz):
    nibbles = matriz_em_nibbles(matriz)
    return ''.join(f'{n:X}' for n in nibbles)

# Algoritmo de encriptação S-AES
def encriptacao(lista_nibble, chave_nibble):
    resultado = nibbles_em_matriz(lista_nibble)
    rodada_chave = key_expansion(chave_nibble)

    print("Estado inicial: ", matriz_em_hex(resultado))
    resultado = add_round_key(resultado, rodada_chave[0])

    print("AddRoundKey: ", matriz_em_hex(resultado))

    # Primeira Rodada
    print("PRIMEIRA RODADA")

    resultado = sub_nibbles(resultado)
    print("SubNibbles: ", matriz_em_hex(resultado))

    resultado = shift_rows(resultado)
    print("ShiftRows: ", matriz_em_hex(resultado))

    resultado = mix_columns(resultado)
    print("MixColumns: ", matriz_em_hex(resultado))

    state = add_round_key(resultado, rodada_chave[1])
    print("AddRoundKey 2: ", matriz_em_hex(resultado))

    # Segunda Rodada
    print("SEGUNDA RODADA")

    resultado = sub_nibbles(resultado)
    print("SubNibbles: ", matriz_em_hex(resultado))
    resultado = shift_rows(resultado)
    print("ShiftRows: ", matriz_em_hex(resultado))
    resultado = add_round_key(resultado, rodada_chave[2])
    print("AddRoundKey 2: ", matriz_em_hex(resultado))

    return matriz_em_nibbles(resultado)

# Mensagem ---------------------------------------------------------
mensagem = "ABC"
chave = "chave"

print("\nParte 1 ---------------------------")
mensagem_bits = string_em_bits(mensagem).ljust(16,"0")[:16]
chave_bits = string_em_bits(chave).ljust(16,"0")[:16]

mensagem_nibbles = definicao_nibbles(mensagem_bits)
chave_nibbles = definicao_nibbles(chave_bits)

cifra_nibble = encriptacao(mensagem_nibbles, chave_nibbles)

cifra_hexadecimal = ''
for n in cifra_nibble:
    hex_num = format(n, 'X')
    cifra_hexadecimal += hex_num

cifra_bytes = bytes(cifra_nibble)
cifra_b64 = base64.b64encode(cifra_bytes).decode()

print("Texto cifrado em hexadecimal: ", cifra_hexadecimal)
print("Texto cifrado em base64: ", cifra_b64)


# =================================================================
# Parte 2 ---------------------------------------------------------
# =================================================================

def encrypt_saes_ecb(msg, chave):
    chave_bits = string_em_bits(chave).ljust(16, "0")[:16]
    chave_nibbles = definicao_nibbles(chave_bits)

    msg_bits = string_em_bits(msg)

    blocos = []
    for i in range(0, len(msg_bits), 16):
        bloco = msg_bits[i:i+16]
        blocos.append(bloco)

    lista_cifrada = []

    for bloco in blocos:
        # Se o bloco for menor que 16, adiciona 0s
        bloco = bloco.ljust(16, "0")

        bloco_nibbles = definicao_nibbles(bloco)
        cifra_nibble = encriptacao(bloco_nibbles, chave_nibbles)

        # Nibbles em bytes
        cifra_bytes = bytes(cifra_nibble)
        lista_cifrada.append(cifra_bytes)

    # Agrupa os blocos cifrados em bytes
    cifra_final = b''.join(lista_cifrada)

    cifra_base64 = base64.b64encode(cifra_final).decode()
    return cifra_base64

mensagem_teste_multiplos_blocos = "ABCABC"
chave_teste_multiplos_blocos = "chave"

print("\nParte 2 ---------------------------")
resultado = encrypt_saes_ecb(mensagem_teste_multiplos_blocos, chave_teste_multiplos_blocos)
print("Texto cifrado em Base64:", resultado)


# =================================================================
# Parte 3 ---------------------------------------------------------
# =================================================================

print("\nParte 3 ---------------------------")

mensagem = "Mensagem teste para AES"

while len(mensagem) % 16 != 0:
    mensagem += ' '

mensagem = mensagem.encode()

# Chaves aleatorias
chave = os.urandom(16)
chave_iv = os.urandom(16)

print("Chave gerada em hex:", chave.hex())
print("IV gerado em hex:", chave_iv.hex())

def base64_encode(data):
    return base64.b64encode(data).decode()

print("------ECB------")
inicio = time.time()
cifrar = Cipher(algorithms.AES(chave), modes.ECB(), backend=default_backend())
encriptar = cifrar.encryptor()
cifrado = encriptar.update(mensagem) + encriptar.finalize()

fim = time.time()

print("Cifragem em Base64:", base64_encode(cifrado))
print("Tempo:", round(fim - inicio, 6), "s")


print("------CBC------")
inicio = time.time()
cifrar = Cipher(algorithms.AES(chave), modes.CBC(chave_iv), backend=default_backend())
encriptar = cifrar.encryptor()
cifrado = encriptar.update(mensagem) + encriptar.finalize()

fim = time.time()

print("Cifragem em Base64:", base64_encode(cifrado))
print("Tempo:", round(fim - inicio, 6), "s")

print("------CFB------")
inicio = time.time()
cifrar = Cipher(algorithms.AES(chave), modes.CFB(chave_iv), backend=default_backend())
encriptar = cifrar.encryptor()
cifrado = encriptar.update(mensagem) + encriptar.finalize()
fim = time.time()

print("Cifragem em Base64:", base64_encode(cifrado))
print("Tempo:", round(fim - inicio, 6), "s")

print("------OFB------")
inicio = time.time()
cifrar = Cipher(algorithms.AES(chave), modes.OFB(chave_iv), backend=default_backend())
encriptar = cifrar.encryptor()
cifrado = encriptar.update(mensagem) + encriptar.finalize()
fim = time.time()

print("Cifragem em Base64):", base64_encode(cifrado))
print("Tempo:", round(fim - inicio, 6), "s")


print("------CTR------")
inicio = time.time()
cifrar = Cipher(algorithms.AES(chave), modes.CTR(chave_iv), backend=default_backend())
encriptar = cifrar.encryptor()
cifrado = encriptar.update(mensagem) + encriptar.finalize()
fim = time.time()

print("Cifragem em Base64:", base64_encode(cifrado))
print("Tempo:", round(fim - inicio, 6), "s")
