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

private_key_secret = 114103586456018184383645221840337368004862442067072313390677100246647035118692
private_key = PrivateKey(secret=private_key_secret%P)

btcVersion = '01000000'
oneAsVarInt = '01' # page 92 Programming bitcoin
timelock = '00000000' # transaction is immediately sent page 94 Programming bitcoin, otherwise the number of blocks you would have to wait
sequence = 'fdffffff' # value doesn't matter if timelock is zero

previousTransactionId = reverse_hex_string_and_every_two_chars_to_swap_endianness('4a791950454232905f2446aaa152ebe99a5f4e61ac80632badb0cfd0db4b74f7') # the previous transaction output 
previousTransactionOutput = '080701d594c1bda163560b67d254c8aa74bd032f' #look on blockchain for this, it is the output that is now being spent as an input
previousTransactionIndex = '00000000' # think this is correct one output from prev transactrion 
amountToSend1 = reverse_hex_string_and_every_two_chars_to_swap_endianness(sats_in_hex("2500"))
destinationAddress1 = hex(base58.b58decode_int('1jSoQG2iMAd8vLmrExeRnwqKvktE65yYi'))[2:-8] # this can have a zero in front of it so its there is a zero in the front need to maintain it such as "080701d594c1bda163560b67d254c8aa74bd032f"
if(len(str(destinationAddress1)) == 39):
    destinationAddress1 = "0" + destinationAddress1

amountToSendZero = reverse_hex_string_and_every_two_chars_to_swap_endianness(sats_in_hex("0")) 

# script operations (assembly language stack)
scriptOperationCheckSig_ac = 'ac'
scriptOperationDuplicate_76 = '76'
scriptOperationHash160_a9 = 'a9'
scriptOperationEqualVerify_88 = '88'
scriptOperationRETURN_6a = '6a'
scriptOperationPushData1 = '4c'

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

PkScriptSendMessage = (scriptOperationRETURN_6a
                        + 
                       #scriptOperationPushData1 +
                       count_hex_bytes("22536F757468204361726F6C696E6120456D657267696E672054656368204173736F632E207468696E6B7320626974636F696E206973207072657474792067726561742122") + 
                       "22536F757468204361726F6C696E6120456D657267696E672054656368204173736F632E207468696E6B7320626974636F696E206973207072657474792067726561742122"
                       )


twoAsVarInt = '02'

print(count_hex_bytes(PkScriptSendMessage))

toSign = (btcVersion + oneAsVarInt + # one since spending one output
          previousTransactionId + previousTransactionIndex + 
          count_hex_bytes(PkScriptPreviousTransaction) + PkScriptPreviousTransaction + sequence + 
          twoAsVarInt +
          amountToSend1 + # first
          count_hex_bytes(PkScriptSend1) + PkScriptSend1 + 
          amountToSendZero + # second
          count_hex_bytes(PkScriptSendMessage) + PkScriptSendMessage + 
          timelock)

seqInt = "4294967293"
print(hex(int(seqInt)))

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

signedTransaction = (btcVersion + oneAsVarInt + # one since spending one output
                     previousTransactionId + previousTransactionIndex + 
                     count_hex_bytes(SignatureScript) + SignatureScript + sequence + 
                     twoAsVarInt + # two outputs
                     amountToSend1 + count_hex_bytes(PkScriptSend1) + PkScriptSend1 +
                     amountToSendZero + count_hex_bytes(PkScriptSendMessage) + PkScriptSendMessage +
                     timelock)

signedTransaction = signedTransaction.lower()

expected2 = '0100000001f7744bdbd0cfb0ad2b6380ac614e5f9ae9eb52a1aa46245f903242455019794a000000006b483045022100a77a792120ccb38a79ff6a83983086ca19817029250a9f6c605782bba941661e022053f7bc2b53dc708e254274f7e7fc6217253c305050ec2cd8c242798df51d7848012103ff41e2f9b5a2b0c577f23b3a0333f89c61206356826b86807f052a6eb8f4fcd0fdffffff02c4090000000000001976a914080701d594c1bda163560b67d254c8aa74bd032f88ac0000000000000000476a4522536f757468204361726f6c696e6120456d657267696e672054656368204173736f632e207468696e6b7320626974636f696e20697320707265747479206772656174212200000000' # https://blockstream.info/api/tx/925d2d21b7a6dc0867521da5c8fce86c093d68cf81d510d5651b3c6ed4ac1d34/hex
#expected = (urllib.request.urlopen("https://blockstream.info/api/tx/925d2d21b7a6dc0867521da5c8fce86c093d68cf81d510d5651b3c6ed4ac1d34/hex").read()).decode("utf-8")
print(signedTransaction)
print(count_chars_and_checksum(signedTransaction))

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