import tkinter as tk
from tkinter import font
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto import Random
import base64
import numpy as np

def aes_encrypt():
    text = aes_input.get()
    newText = text + (16 - len(text) % 16) * '*'
    key = Random.new().read(16)
    iv = Random.new().read(16)
    E = AES.new(key, AES.MODE_CBC, iv)
    encryptionMessage = base64.b64encode(E.encrypt(newText.encode('utf-8')))
    aes_output.delete('1.0', tk.END)
    aes_output.insert(tk.END, f"Key: {key}\nEncryption Message: {encryptionMessage}")
    # Create a label to display the result
    aes_result_label = ttk.Label(aes_tab, text="Result:")
    aes_result_label.pack()
    aes_result = ttk.Label(aes_tab, text=f"Key: {key}\nEncryption Message: {encryptionMessage}")
    aes_result.pack()

def caeser_encrypt():
    text = caeser_input.get()
    sh = int(caeser_shift.get())
    res = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            res += chr((ord(char) + sh - 65) % 26 + 65)
        elif char.islower():
            res += chr((ord(char) + sh - 97) % 26 + 97)
        else:
            res += char
    caeser_output.delete('1.0', tk.END)
    caeser_output.insert(tk.END, res.upper())
    # Create a label to display the result
    caeser_result_label = ttk.Label(caeser_tab, text="Result:")
    caeser_result_label.pack()
    caeser_result = ttk.Label(caeser_tab, text=res.upper())
    caeser_result.pack()

def vigener_encrypt():
    def get_key(text, key):
        newKey = key
        if len(text) > len(key):
            for i in range(len(text) - len(key)):
                newKey += key[i % len(key)]
        return newKey

    def encrypt_text(text, newKey):
        newText = ""
        for i in range(len(text)):
            newText += chr((ord(text[i]) + ord(newKey[i])) % 26 + 65)
        return newText

    text = vigener_input.get().upper()
    key = vigener_key.get().upper()
    newKey = get_key(text, key)
    vigener_output.delete('1.0', tk.END)
    vigener_output.insert(tk.END, encrypt_text(text, newKey))
    # Create a label to display the result
    vigener_result_label = ttk.Label(vigener_tab, text="Result:")
    vigener_result_label.pack()
    vigener_result = ttk.Label(vigener_tab, text=encrypt_text(text, newKey))
    vigener_result.pack()

def playfair_encrypt():
    def convert_plain_text_to_digraphs(plainText):
        for s in range(0, len(plainText) + 1, 2):
            if s < len(plainText) - 1:
                if plainText[s] == plainText[s + 1]:
                    plainText = plainText[:s + 1] + 'X' + plainText[s + 1:]
        if len(plainText) % 2 != 0:
            plainText = plainText[:] + 'X'
        return plainText

    def generate_key_matrix(key):
        matrix_5x5 = [[0 for i in range(5)] for j in range(5)]
        simpleKeyArr = []
        for c in key:
            if c not in simpleKeyArr:
                if c == 'J':
                    simpleKeyArr.append('I')
                else:
                    simpleKeyArr.append(c)

        is_I_exist = "I" in simpleKeyArr
        for i in range(65, 91):
            if chr(i) not in simpleKeyArr:
                if i == 73 and not is_I_exist:
                    simpleKeyArr.append("I")
                    is_I_exist = True
                elif i == 73 or i == 74 and is_I_exist:
                    pass
                else:
                    simpleKeyArr.append(chr(i))
        index = 0
        for i in range(0, 5):
            for j in range(0, 5):
                matrix_5x5[i][j] = simpleKeyArr[index]
                index += 1
        return matrix_5x5

    def index_locator(char, cipherKeyMatrix):
        indexOfChar = []
        if char == "J":
            char = "I"
        for i, j in enumerate(cipherKeyMatrix):
            for k, l in enumerate(j):
                if char == l:
                    indexOfChar.append(i)
                    indexOfChar.append(k)
                    return indexOfChar

    def encryption(plainText, key):
        cipherText = []
        keyMatrix = generate_key_matrix(key)
        i = 0
        while i < len(plainText):
            n1 = index_locator(plainText[i], keyMatrix)
            n2 = index_locator(plainText[i + 1], keyMatrix)
            if n1[1] == n2[1]:
                i1 = (n1[0] + 1) % 5
                j1 = n1[1]
                i2 = (n2[0] + 1) % 5
                j2 = n2[1]
                cipherText.append(keyMatrix[i1][j1])
                cipherText.append(keyMatrix[i2][j2])
                cipherText.append(", ")
            elif n1[0] == n2[0]:
                i1 = n1[0]
                j1 = (n1[1] + 1) % 5
                i2 = n2[0]
                j2 = (n2[1] + 1) % 5
                cipherText.append(keyMatrix[i1][j1])
                cipherText.append(keyMatrix[i2][j2])
                cipherText.append(", ")
            else:
                i1 = n1[0]
                j1 = n1[1]
                i2 = n2[0]
                j2 = n2[1]
                cipherText.append(keyMatrix[i1][j2])
                cipherText.append(keyMatrix[i2][j1])
                cipherText.append(", ")
            i += 2
        return cipherText

    key = playfair_key.get().replace(" ", "").upper()
    plainText = playfair_input.get().replace(" ", "").upper()
    convertedPlainText = convert_plain_text_to_digraphs(plainText)
    cipherText = " ".join(encryption(convertedPlainText, key))
    playfair_output.delete('1.0', tk.END)
    playfair_output.insert(tk.END, cipherText)
     # Create a label to display the result
    playfair_result_label = ttk.Label(playfair_tab, text="Result:")
    playfair_result_label.pack()
    playfair_result = ttk.Label(playfair_tab, text=cipherText)
    playfair_result.pack()


def hill_cipher_encrypt():
    def hill_cipher(plain_text, key):
        key_length = len(key)
        square_size = int(key_length ** 0.5)
        key_int = [ord(char) - 65 for char in key]
        key_matrix = np.array(key_int).reshape(square_size, square_size)
        if len(plain_text) % square_size != 0:
            plain_text += "X" * (square_size - len(plain_text) % square_size)
        cipher_text = ""
        for i in range(0, len(plain_text), square_size):
            block = [ord(char) - 65 for char in plain_text[i:i + square_size]]
            encrypted_block = np.dot(key_matrix, block) % 26
            encrypted_chars = "".join([chr(value + 65) for value in encrypted_block])
            cipher_text += encrypted_chars
        return cipher_text

    plain_text = hill_input.get()
    key = hill_key.get()
    cipher_text = hill_cipher(plain_text, key)
    hill_output.delete('1.0', tk.END)
    hill_output.insert(tk.END, cipher_text)
    # Create a label to display the result
    hill_result_label = ttk.Label(hill_tab, text="Result:")
    hill_result_label.pack()
    hill_result = ttk.Label(hill_tab, text=cipher_text)
    hill_result.pack()

root = tk.Tk()
root.title("Encryption GUI")

# Create the tabs
tab_control = ttk.Notebook(root)

# Create the AES tab
aes_tab = ttk.Frame(tab_control)
aes_tab.grid(sticky="nsew")
aes_label = ttk.Label(aes_tab, text="AES Encryption")
aes_label.pack(pady=10)
aes_input_label = ttk.Label(aes_tab, text="Enter Your Message:")
aes_input_label.pack()
aes_input = ttk.Entry(aes_tab, width=50)
aes_input.pack(pady=5)
aes_button = ttk.Button(aes_tab, text="Encrypt", command=aes_encrypt)
aes_button.pack(pady=10)
aes_output_label = ttk.Label(aes_tab, text="Encrypted Message:")
aes_output_label.pack()
aes_output = tk.Text(aes_tab, height=5, width=50)
aes_output.pack(pady=5)
aes_output.configure(state="disabled")

# Create the Caeser tab
caeser_tab = ttk.Frame(tab_control)
caeser_tab.grid(sticky="nsew")
caeser_label = ttk.Label(caeser_tab, text="Caeser Encryption")
caeser_label.pack(pady=10)
caeser_input_label = ttk.Label(caeser_tab, text="Enter Your Text:")
caeser_input_label.pack()
caeser_input = ttk.Entry(caeser_tab, width=50)
caeser_input.pack(pady=5)
caeser_shift_label = ttk.Label(caeser_tab, text="Enter Shift:")
caeser_shift_label.pack()
caeser_shift = ttk.Entry(caeser_tab, width=50)
caeser_shift.pack(pady=5)
caeser_button = ttk.Button(caeser_tab, text="Encrypt", command=caeser_encrypt)
caeser_button.pack(pady=10)
caeser_output_label = ttk.Label(caeser_tab, text="Encrypted Text:")
caeser_output_label.pack()
caeser_output = tk.Text(caeser_tab, height=5, width=50)
caeser_output.pack(pady=5)
caeser_output.configure(state="disabled")

# Create the Vigenere tab
vigener_tab = ttk.Frame(tab_control)
vigener_tab.grid(sticky="nsew")
vigener_label = ttk.Label(vigener_tab, text="Vigenere Encryption")
vigener_label.pack(pady=10)
vigener_input_label = ttk.Label(vigener_tab, text="Enter Your Text:")
vigener_input_label.pack()
vigener_input = ttk.Entry(vigener_tab, width=50)
vigener_input.pack(pady=5)
vigener_key_label = ttk.Label(vigener_tab, text="Enter Your Key:")
vigener_key_label.pack()
vigener_key = ttk.Entry(vigener_tab, width=50)
vigener_key.pack(pady=5)
vigener_button = ttk.Button(vigener_tab, text="Encrypt", command=vigener_encrypt)
vigener_button.pack(pady=10)
vigener_output_label = ttk.Label(vigener_tab, text="Encrypted Text:")
vigener_output_label.pack()
vigener_output = tk.Text(vigener_tab, height=5, width=50)
vigener_output.pack(pady=5)
vigener_output.configure(state="disabled")

# Create the Playfair tab
playfair_tab = ttk.Frame(tab_control)
playfair_tab.grid(sticky="nsew")
playfair_label = ttk.Label(playfair_tab, text="Playfair Encryption")
playfair_label.pack(pady=10)
playfair_input_label = ttk.Label(playfair_tab, text="Enter Your Text:")
playfair_input_label.pack()
playfair_input = ttk.Entry(playfair_tab, width=50)
playfair_input.pack(pady=5)
playfair_key_label = ttk.Label(playfair_tab, text="Enter Your Key:")
playfair_key_label.pack()
playfair_key = ttk.Entry(playfair_tab, width=50)
playfair_key.pack(pady=5)
playfair_button = ttk.Button(playfair_tab, text="Encrypt", command=playfair_encrypt)
playfair_button.pack(pady=10)
playfair_output_label = ttk.Label(playfair_tab, text="Encrypted Text:")
playfair_output_label.pack()
playfair_output = tk.Text(playfair_tab, height=5, width=50)
playfair_output.pack(pady=5)
playfair_output.configure(state="disabled")

# Create the Hill Cipher tab
hill_tab = ttk.Frame(tab_control)
hill_tab.grid(sticky="nsew")
hill_label = ttk.Label(hill_tab, text="Hill Cipher Encryption")
hill_label.pack(pady=10)
hill_input_label = ttk.Label(hill_tab, text="Enter Your Text:")
hill_input_label.pack()
hill_input = ttk.Entry(hill_tab, width=50)
hill_input.pack(pady=5)
hill_key_label = ttk.Label(hill_tab, text="Enter Your Key:")
hill_key_label.pack()
hill_key = ttk.Entry(hill_tab, width=50)
hill_key.pack(pady=5)
hill_button = ttk.Button(hill_tab, text="Encrypt", command=hill_cipher_encrypt)
hill_button.pack(pady=10)
hill_output_label = ttk.Label(hill_tab, text="Encrypted Text:")
hill_output_label.pack()
hill_output = tk.Text(hill_tab, height=5, width=50)
hill_output.pack(pady=5)
hill_output.configure(state="disabled")

# Add the tabs to the tab control
tab_control.add(aes_tab, text="AES")
tab_control.add(caeser_tab, text="Caeser")
tab_control.add(vigener_tab, text="Vigenere")
tab_control.add(playfair_tab, text="Playfair")
tab_control.add(hill_tab, text="Hill Cipher")

# Pack the tab control
tab_control.pack(expand=1, fill="both")

root.mainloop()
