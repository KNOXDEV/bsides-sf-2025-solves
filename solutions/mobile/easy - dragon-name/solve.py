#!/usr/bin/env python3
import codecs
import base64

def create_flag():
    # Part 1: ROT13 of "PGS"
    part1 = codecs.decode("PGS", 'rot_13')
    
    # Part 2: Base64 decode of "dzNhaw=="
    b64 = base64.b64decode("dzNhaw==")
    part2 = b64.decode('utf-8')
    
    # Part 3: Literal string
    part3 = "T0"
    
    # Part 4: From resources (strings.xml)
    part4 = "Fa1ry"
    
    # Part 5: Literal string
    part5 = "Typ3"
    
    # Construct the flag
    flag = part1 + "{" + part2 + part3 + part4 + part5 + "}"
    return flag

if __name__ == "__main__":
    print(create_flag())
