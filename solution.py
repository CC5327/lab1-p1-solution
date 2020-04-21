import decimal
from decimal import Decimal
from math import sqrt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import constants
import utils

if __name__ == "__main__":
    pk = utils.load_public_key_file(constants.PUBLIC_KEY_PATH)
    ctx = decimal.getcontext()
    ctx.prec = 1 << 12
    print("precision is {}".format(ctx.prec))
    n = Decimal(utils.get_n(pk), ctx)
    n_sqrt = n.sqrt(ctx).to_integral_exact()
    p = 0
    q = 0
    print("Finding factors")
    i = 0
    while True:
        i += 1
        if i % 10000 == 0:
            print("try n° {}, we are in {}".format(i, n_sqrt))
        if n % n_sqrt == 0:
            q = n_sqrt
            print("found first factor!", q)
            break
        n_sqrt += 1
    p = n // q
    print("found second factor!", p)
    sk = utils.new_fixed_rsa_key(int(p), int(q))
    with open(constants.CIPHERED_PATH, 'rb') as f:
        ciphered = f.read()
        deciphered = sk.decrypt(ciphered, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
        print("deciphered text is %s", deciphered)
