from Crypto.PublicKey import ECC

key = ECC.generate(curve = 'P-256')

with open("data/server_private_key.der", "wb") as f:
    f.write(key.export_key(format = "DER"))

with open("data/server_public_key.der", "wb") as f:
    f.write(key.public_key().export_key(format = "DER"))
