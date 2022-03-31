#A stratum compatible miniminer
#based in the documentation
#https://slushpool.com/help/#!/manual/stratum-protocol
#2017-2019 Martin Nadal https://martinnadal.eu

import socket
import json
import hashlib
import binascii
from pprint import pprint
import time
import random
import tdc_yespower


def target_to_bits(target: int) -> int:
    c = ("%066x" % target)[2:]
    while c[:2] == '00' and len(c) > 6:
        c = c[2:]
    bitsN, bitsBase = len(c) // 2, int.from_bytes(bfh(c[:6]), byteorder='big')
    if bitsBase >= 0x800000:
        bitsN += 1
        bitsBase >>= 8
    return bitsN << 24 | bitsBase


def bits_to_target(bits: int) -> int:
    bitsN = (bits >> 24) & 0xff
    if not (0x03 <= bitsN <= 0x20):
        raise Exception("First part of bits should be in [0x03, 0x1d]")
    bitsBase = bits & 0xffffff
    if not (0x8000 <= bitsBase <= 0x7fffff):
        raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
    return bitsBase << (8 * (bitsN - 3))

def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return x.hex()

def hash_encode(x: bytes) -> str:
    return bh2u(x[::-1])


bfh = bytes.fromhex


address = 'TSrAZcfyx8EZdzaLjV5ketPwtowgw3WUYw'


host    = 'pool.tidecoin.exchange'
port    = 3033

print("address:{}".format(address))
print("host:{} port:{}".format(host,port))

sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host,port))

#server connection
sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
lines = sock.recv(1024).decode().split('\n')
response = json.loads(lines[0])
sub_details,extranonce1,extranonce2_size = response['result']
print(sub_details, extranonce1,extranonce2_size)
#authorize workers
sock.sendall(b'{"params": ["'+address.encode()+b'", "password"], "id": 2, "method": "mining.authorize"}\n')

#we read until 'mining.notify' is reached
while True:
    response = b''

    while response.count(b'\n') < 4 and not(b'mining.notify' in response):
        comeback = sock.recv(1024)
        response += comeback
        print(comeback)


    #get rid of empty lines
    responses = [json.loads(res) for res in response.decode().split('\n') if len(res.strip())>0 and 'mining.notify' in res]
    pprint(responses)

    job_id,prevhash,coinb1,coinb2,merkle_branch,version,nbits,ntime,clean_jobs \
        = responses[0]['params']

    #target https://bitcoin.stackexchange.com/a/36228/44319

    target = bits_to_target(target_to_bits(int(nbits, 16)))
    print('nbits:{} target:{}\n'.format(nbits,target))

    extranonce2 = '00'*extranonce2_size

    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    print('coinbase:\n{}\n\ncoinbase hash:{}\n'.format(coinbase, binascii.hexlify(coinbase_hash_bin)))
    merkle_root = coinbase_hash_bin
    for h in merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

    merkle_root = binascii.hexlify(merkle_root).decode()

    #little endian
    merkle_root = ''.join([merkle_root[i]+merkle_root[i+1] for i in range(0,len(merkle_root),2)][::-1])

    print('merkle_root:{}\n'.format(merkle_root))

    nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)
    blockheader = version + prevhash + merkle_root + ntime + nbits
    print('blockheader:\n{}\n'.format(blockheader + nonce+\
        '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'))

    hash = tdc_yespower.getPoWHash(bfh(blockheader + nonce+\
        '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'))

    counter = 0
    tima = time.time()
    while int.from_bytes(bfh(hash_encode(hash)), byteorder='big') > 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff*0.05:
        nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)
        hash = tdc_yespower.getPoWHash(bfh(blockheader+ nonce+\
        '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'))
        counter += 1
        if counter == 10000:
            print(time.time()-tima)
            counter = 0
            tima = time.time()

    if int.from_bytes(bfh(hash_encode(hash)), byteorder='big') < 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff*0.05:
        print('success!!')
        payload = '{"params": ["'+address+'", "'+job_id+'", "'+extranonce2 \
            +'", "'+ntime+'", "'+nonce+'"], "id": 1, "method": "mining.submit"}\n'
        sock.sendall(bytes(payload, "UTF-8"))
    else:
        print('failed mine, hash is greater than target')

sock.close()
