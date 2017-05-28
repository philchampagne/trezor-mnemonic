#!/usr/bin/env python

from __future__ import print_function

import json
import sys
from binascii import hexlify, unhexlify
from random import choice, seed
from bip32utils import BIP32Key
import hashlib
import base64

from mnemonic import Mnemonic

def b2h(b):
    h = hexlify(b)
    return h if sys.version < '3' else h.decode('utf8')

def process(data, lst):
    print('input    : %s (%d bits)' % (data, len(data) * 4))
    code = mnemo.to_mnemonic(unhexlify(data))
    seed = Mnemonic.to_seed(code, passphrase='TREZOR')
    xprv = BIP32Key.fromEntropy(seed).ExtendedKey()
    seed = b2h(seed)
    print('input    : %s (%d bits)' % (data, len(data) * 4))
    print('mnemonic : %s (%d words)' % (code, len(code.split(' '))))
    print('seed     : %s (%d bits)' % (seed, len(seed) * 4))
    print('xprv     : %s' % xprv)
    print()
    lst.append((data, code, seed, xprv))

def usage():
    print("Usage: genfw.py word1 word2 ... wordn")
    print("   where word1, word2 is your own words, as many as you want")
    print("   Need at least 10 words")
    print("   Example: all words of 5 characters or more from a ")
    print("     paragraph of a book you have + a simple word of your own")


if __name__ == '__main__':
    out = {}
    numargs = len(sys.argv)
    cmdargs = str(sys.argv)
    if numargs < 2:
	print("Missing arguments")
	usage()
	sys.exit(1)

    if numargs < 10:
	print("Warning: you should consider providing 10 words or more")

    words = ""
    i = 1
    while True:
	words += str(sys.argv[i])
	i += 1
	if i >= numargs:
	    break
	words += " "

    print('Words supplied: %s' % (words))

    for lang in ['english']: # Mnemonic.list_languages():
        mnemo = Mnemonic(lang)
        out[lang] = []

        data = []
        # Create data entry from words
	hash_obj = hashlib.sha256(words)
	seedhex = hash_obj.hexdigest()
	seedhex2= '9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863'
	print('seedhex=%s' % str(seedhex))
        process(seedhex, out[lang])
	

    with open('vectors.json', 'w') as f:
        json.dump(out, f, sort_keys=True, indent=4, separators=(',', ': '), ensure_ascii=False)
