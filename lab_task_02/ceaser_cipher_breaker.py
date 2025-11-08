import string

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    alphabet = string.ascii_lowercase
    decrypted = ""
    for char in ciphertext:
        if char in alphabet:
            decrypted += alphabet[(alphabet.index(char) - shift) % 26]
        else:
            decrypted += char
    return decrypted


def break_caesar(ciphertext: str):
    results = []
    for shift in range(26):
        results.append((shift, caesar_decrypt(ciphertext, shift)))
    return results

# testing the function
cipher = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"
possible_texts = break_caesar(cipher)

for shift, text in possible_texts:
    print(f"Shift {shift}: {text}")
