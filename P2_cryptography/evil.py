#!/usr/bin/python3
# coding: latin-1
blob = """
                ؚ���?.�B������ђ�p˄C~A~ԤD�I���Ƀ˗�:Y�<�Jl��S� T��^�}v�ݥXJg�1C�Iw;�e3��|@'͡��"}��I[=��';��g�DR��(\�,��m����iΩ5
"""
from hashlib import sha256
val = sha256(blob.encode("latin-1")).hexdigest()
if val == "f3f173384324b6f7a1e7f2be91611a9faf08f3743e4fe2a13114ed150f12f935":
    print("Use SHA-256 instead!")
else:
    print("MD5 is perfectly secure!")