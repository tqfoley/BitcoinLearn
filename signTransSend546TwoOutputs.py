from io import BytesIO
import base58
import urllib.request
# Chapter 13 from Programming Bitcoin book https://github.com/jimmysong/programmingbitcoin/blob/master/ch13.asciidoc
from ch13.helper import hash256
from ch13.tx import Tx
from ch13.ecc import S256Point, PrivateKey, Signature
from myhelper import count_hex_bytes, reverse_hex_string_and_every_two_chars_to_swap_endianness, count_chars_and_checksum, sats_in_hex

P = 2**256 - 2**32 - 977 # prime for finite field
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

private_key = PrivateKey(secret=82415795305589498003082988153531328196693446478344872211098781929772307350017%P)  

btcVersion = '01000000'
oneAsVarInt = '01' # page 92 Programming bitcoin
timelock = '00000000' # transaction is immediately sent page 94 Programming bitcoin, otherwise the number of blocks you would have to wait
sequence = 'fdffffff' # value doesn't matter if timelock is zero

#this transaction 4d518e13dbfab9d1a6ccbf0dbb8dc58866471a8ea1777512954b4f44e3bcc45e from 1EHp4zm1T2yUyjEmW3H4qauTJiVEXan3Uf
previousTransactionId = reverse_hex_string_and_every_two_chars_to_swap_endianness('d9eb3f1982e87d2a9cbc422d7db2d95c59b12dd6e19df37a8b9bc3b273454cdc') # the previous transaction output 
previousTransactionOutput = '91c794eb0d1b7760639b7c5a863521b09c31d4de' #look on blockchain for this, it is the output that is now being spent as an input
previousTransactionIndex = '00000000' # think this is correct one output from prev transactrion 
amountToSend1 = reverse_hex_string_and_every_two_chars_to_swap_endianness(sats_in_hex("546")) 
destinationAddress1 = hex(base58.b58decode_int('1BVyTe8ofZqYt5bDVSck4K7XGMEFiEHEm1'))[2:-8]
amountToSend2 =reverse_hex_string_and_every_two_chars_to_swap_endianness(sats_in_hex("632"))
destinationAddress2 = hex(base58.b58decode_int('1HtRFnmpAcaEi9sh3yzsESzUtMRkqjpxss'))[2:-8]

#amountToSendTotal = reverse_hex_string_and_every_two_chars_to_swap_endianness('000000000000049a') #222 + 278

# script operations (assembly language stack)
scriptOperationCheckSig_ac = 'ac'
scriptOperationDuplicate_76 = '76'
scriptOperationHash160_a9 = 'a9'
scriptOperationEqualVerify_88 = '88'

sigHashAllOneByte = '01'
sigHashAll = '01000000' # most common

#Pkscript
#OP_DUP
#OP_HASH160
# previous output address
#OP_EQUALVERIFY
#OP_CHECKSIG
PkScriptPreviousTransaction = (scriptOperationDuplicate_76 +
                               scriptOperationHash160_a9 +
                               count_hex_bytes(previousTransactionOutput) +
                               previousTransactionOutput +
                               scriptOperationEqualVerify_88 +
                               scriptOperationCheckSig_ac)

#Pkscript
#OP_DUP
#OP_HASH160
# destination address
#OP_EQUALVERIFY
#OP_CHECKSIG
PkScriptSend1 = (scriptOperationDuplicate_76 +
                scriptOperationHash160_a9 +
                count_hex_bytes(destinationAddress1) +
                destinationAddress1 +
                scriptOperationEqualVerify_88 +
                scriptOperationCheckSig_ac)

PkScriptSend2 = (scriptOperationDuplicate_76 +
                scriptOperationHash160_a9 +
                count_hex_bytes(destinationAddress2) +
                destinationAddress2 +
                scriptOperationEqualVerify_88 +
                scriptOperationCheckSig_ac)

twoAsVarInt = '02'

toSign = (btcVersion + oneAsVarInt + # one since spending one output
          previousTransactionId + previousTransactionIndex + 
          count_hex_bytes(PkScriptPreviousTransaction) + PkScriptPreviousTransaction + sequence + 
          twoAsVarInt +
          amountToSend1 + # first
          count_hex_bytes(PkScriptSend1) + PkScriptSend1 + 
          amountToSend2 + # second
          count_hex_bytes(PkScriptSend2) + PkScriptSend2 + 
          timelock)

seqInt = "4294967293"
print(hex(int(seqInt)))

toSignReversed = (btcVersion + oneAsVarInt + # one since spending one output
          previousTransactionId + previousTransactionIndex + 
          count_hex_bytes(PkScriptPreviousTransaction) + PkScriptPreviousTransaction + sequence + 
          twoAsVarInt +
          amountToSend2 + # first
          count_hex_bytes(PkScriptSend2) + PkScriptSend2 +
          amountToSend1 + # second
          count_hex_bytes(PkScriptSend1) + PkScriptSend1 + 
          timelock)

print("toSign")
print(count_chars_and_checksum(toSign))

def signTrans(private, z):
    k = private.deterministic_k(z)
    # r is the x coordinate of the resulting point k*G
    r = (k * G).x.num
    # remember 1/k = pow(k, N-2, N)
    k_inv = pow(k, N - 2, N)
    # s = (z+r*secret) / k
    s = (z + r * private.secret) * k_inv % N
    if s > N / 2:
        s = N - s
    # return an instance of Signature:
    # Signature(r, s)
    return Signature(r, s)

tx_obj = Tx.parse(BytesIO(bytes.fromhex(toSign)), testnet=False)
z = tx_obj.sig_hash(0)
derhex = signTrans(private_key, z).der().hex()
sechex = private_key.point.sec().hex()

SignatureScript = count_hex_bytes(derhex + sigHashAllOneByte) + derhex + sigHashAllOneByte + count_hex_bytes(sechex) + sechex

print("SignatureScript          " + count_chars_and_checksum(SignatureScript))
print("SignatureScript Expected " + count_chars_and_checksum("4830450221009c45f28798f848b04652753aafd675cb637157dd98332592d17392c40e6d90f80220612f3e2b5603e303569b8e01b7aba49fb328893047fd100b274360857c97aa350121039024fc4cc4350491cc38a0a2678b701a20f905254ae33cd5393e020d91dd9af1"))

signedTransaction = (btcVersion + oneAsVarInt + # one since spending one output
                     previousTransactionId + previousTransactionIndex + 
                     count_hex_bytes(SignatureScript) + SignatureScript + sequence + 
                     twoAsVarInt + # two outputs
                     amountToSend1 + count_hex_bytes(PkScriptSend1) + PkScriptSend1 +
                     amountToSend2 + count_hex_bytes(PkScriptSend2) + PkScriptSend2 +
                     timelock)
expected2 = '0100000001dc4c4573b2c39b8b7af39de1d62db1595cd9b27d2d42bc9c2a7de882193febd9000000006b4830450221009c45f28798f848b04652753aafd675cb637157dd98332592d17392c40e6d90f80220612f3e2b5603e303569b8e01b7aba49fb328893047fd100b274360857c97aa350121039024fc4cc4350491cc38a0a2678b701a20f905254ae33cd5393e020d91dd9af1fdffffff0222020000000000001976a914732c08dd88640e39b2b254135ff2dab47f76453b88ac78020000000000001976a914b93b79401918af890c623c3d778e920441b13fb988ac00000000' # https://blockstream.info/api/tx/f2f051f538810a205ddf2b1478d50f929dd079550af3cce20827a38dcb9ee9be/hex
expected = (urllib.request.urlopen("https://blockstream.info/api/tx/4d518e13dbfab9d1a6ccbf0dbb8dc58866471a8ea1777512954b4f44e3bcc45e/hex").read()).decode("utf-8")

print(signedTransaction)

if(signedTransaction == expected):
    print('MATCH!')
else:
    print('BAD NO MATCH')

if(signedTransaction == expected2):
    print('MATCH!')
else:
    print('BAD NO MATCH')

h256 = hash256(bytes.fromhex(toSign + sigHashAll))
z = int.from_bytes(h256, 'big')
point = S256Point.parse(bytes.fromhex(sechex))
sig = Signature.parse(bytes.fromhex(derhex))

def verifyTrans( z, sig, s256point):
    # By Fermat's Little Theorem, 1/s = pow(s, N-2, N)
    s_inv = pow(sig.s, N - 2, N)
    # u = z / s
    u = z * s_inv % N
    # v = r / s
    v = sig.r * s_inv % N
    # u*G + v*P should have as the x coordinate, r
    total = u * G + v * s256point
    return total.x.num == sig.r

if(verifyTrans(z, sig, point) == True):
    print('Transaction is valid!')
else:
    print('Error: Not Valid Transaction')