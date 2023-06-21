# DNAS information

With this project we extract the DNAS information for each game that is been used to pass the DNAS check.

## What kind of information we collect?

- Pass phrase: This is been used to decrypt the Authentication data.
- Authentication data: Encrypted file with Public 1024 bits RSA keys stored.
- Modulo: RSA public key modulo(n). This value is the product of 2 unknown large prime factors.
- Exponent: RSA public key exponent(e).
- Breakpoint: Debug address that has the modulo stored

Both Modulo and Exponent are used to decrypt the signature to a message with PKCS1.5.

## What do we want to accomplish?

To make this information public we want to stimulate to get the RSA keys to be cracked.
In the near future there could be a breakthrough in prime factorisation to crack those keys.
Think about Quantum computers as example that can use [QFT](https://en.wikipedia.org/wiki/Quantum_Fourier_transform) to solve this problem.
Also the largest known prime factor that has been publicly factored is in [2020 with 829-bits product](https://en.wikipedia.org/wiki/RSA_numbers#RSA-250).

