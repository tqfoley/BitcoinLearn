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

private_key = PrivateKey(secret=10185666355360570128723759600355014748330344510962090128535490833542411751071%P)

btcVersion = '01000000'
oneAsVarInt = '01' # page 92 Programming bitcoin
timelock = '00000000' # transaction is immediately sent page 94 Programming bitcoin, otherwise the number of blocks you would have to wait
sequence = 'fdffffff' # value doesn't matter if timelock is zero

previousTransactionId = reverse_hex_string_and_every_two_chars_to_swap_endianness('8cefa7cde387a53aafe975047880de3902da40321943584a7dc10839b25b215e') # the previous transaction output we are trying to spend as an input https://www.blockchain.com/explorer/transactions/btc/8cefa7cde387a53aafe975047880de3902da40321943584a7dc10839b25b215e
previousTransactionOutput = 'b2478f4a029c3fa09f71d32ff5a5bbd3bd79b0b7' #look on blockchain for this, it is the output that is now being spent as an input
previousTransactionIndex = '00000000' # zero, it was the first transaction
amountToSend = reverse_hex_string_and_every_two_chars_to_swap_endianness('00000000000002dc') # 0.00000732 BTC  732 / 100 000 000 = 256*2(2) + 16*13(d) + 12(c)  
amountToSend2 = reverse_hex_string_and_every_two_chars_to_swap_endianness(sats_in_hex("732")) 

if(amountToSend != amountToSend2):
    raise ValueError("Should match")


destinationAddress = hex(base58.b58decode_int('1EHp4zm1T2yUyjEmW3H4qauTJiVEXan3Uf'))[2:-8]

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
#b2478f4a029c3fa09f71d32ff5a5bbd3bd79b0b7 previous output address
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
#91c794eb0d1b7760639b7c5a863521b09c31d4de destination address
#OP_EQUALVERIFY
#OP_CHECKSIG
PkScriptSend = (scriptOperationDuplicate_76 +
                scriptOperationHash160_a9 +
                count_hex_bytes(destinationAddress) +
                destinationAddress +
                scriptOperationEqualVerify_88 +
                scriptOperationCheckSig_ac)

toSign = (btcVersion + oneAsVarInt + # one since spending one output
          previousTransactionId + previousTransactionIndex + 
          count_hex_bytes(PkScriptPreviousTransaction) + PkScriptPreviousTransaction + sequence + 
          oneAsVarInt + amountToSend + # one since sending single amount (no change address) extra sats are used for the fee
          count_hex_bytes(PkScriptSend) + PkScriptSend + timelock)

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
print("SignatureScript Expected " + count_chars_and_checksum("4830450221008b1020af415df28930688ca8c70205737605f329efa10e9227ce6f2d93dcdf100220798e3dcd305aeff882b3fce1eeb53e40fb853cbad9685efe45383d4eb5516088012103ec6b306cf02e5e0d8b64574c85fd24b4cd43d85a92e9d36a837aa298245ec586"))

signedTransaction = (btcVersion + oneAsVarInt + # one since spending one output
                     previousTransactionId + previousTransactionIndex + 
                     count_hex_bytes(SignatureScript) + SignatureScript + sequence + 
                     oneAsVarInt + amountToSend + # one since sending single amount (no change address) extra sats are used for the fee
                     count_hex_bytes(PkScriptSend) + PkScriptSend + timelock)
expected2 = '01000000015e215bb23908c17d4a5843193240da0239de80780475e9af3aa587e3cda7ef8c000000006b4830450221008b1020af415df28930688ca8c70205737605f329efa10e9227ce6f2d93dcdf100220798e3dcd305aeff882b3fce1eeb53e40fb853cbad9685efe45383d4eb5516088012103ec6b306cf02e5e0d8b64574c85fd24b4cd43d85a92e9d36a837aa298245ec586fdffffff01dc020000000000001976a91491c794eb0d1b7760639b7c5a863521b09c31d4de88ac00000000' # https://blockstream.info/api/tx/f2f051f538810a205ddf2b1478d50f929dd079550af3cce20827a38dcb9ee9be/hex
#expected = (urllib.request.urlopen("https://blockstream.info/api/tx/f2f051f538810a205ddf2b1478d50f929dd079550af3cce20827a38dcb9ee9be/hex").read()).decode("utf-8")

print("signedTransaction divide by 2 for bytes")
print(count_chars_and_checksum(signedTransaction))

if(signedTransaction == expected2 or signedTransaction == expected2):
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