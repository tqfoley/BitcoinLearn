from io import BytesIO
import base58
import urllib.request
from ch13.helper import hash256
from ch13.tx import Tx
from ch13.ecc import S256Point, PrivateKey, Signature
# Chapter 13 from Programming Bitcoin book https://github.com/jimmysong/programmingbitcoin/blob/master/ch13.asciidoc

def count_hex_bytes(input_string):
    count = int(len(input_string)/2)
    return hex(count)[2:]

def reverse_hex_string_and_every_two_chars_to_swap_endianness(s): # big endian to little endian and vice versa on hexidecimal strings https://en.wikipedia.org/wiki/Endianness
    result = ''
    for i in range(0, len(s), 2):
        pair = s[i:i+2]
        result += pair[::-1]
    return result[::-1]

twoToPower32 = (256*256*256*256)
prime = twoToPower32*twoToPower32*twoToPower32*twoToPower32*twoToPower32*twoToPower32*twoToPower32*twoToPower32 - twoToPower32 - 977
private_key = PrivateKey(secret=10185666355360570128723759600355014748330344510962090128535490833542411751071%prime)

btcVersion = '01000000'
oneAsVarInt = '01' # page 92 Programming bitcoin
timelock = '00000000' # transaction is immediately sent page 94 Programming bitcoin, otherwise the number of blocks you would have to wait
sequence = 'fdffffff' # value doesn't matter if timelock is zero

previousTransactionId = reverse_hex_string_and_every_two_chars_to_swap_endianness('8cefa7cde387a53aafe975047880de3902da40321943584a7dc10839b25b215e') # the previous transaction output we are trying to spend as an input https://www.blockchain.com/explorer/transactions/btc/8cefa7cde387a53aafe975047880de3902da40321943584a7dc10839b25b215e
previousTransactionOutput = 'b2478f4a029c3fa09f71d32ff5a5bbd3bd79b0b7' #look on blockchain for this, it is the output that is now being spent as an input
previousTransactionIndex = '00000000' # zero, it was the first transaction
amountToSend = reverse_hex_string_and_every_two_chars_to_swap_endianness('00000000000002dc') # 0.00000732 BTC  732 / 100 000 000 = 256*2(2) + 16*13(d) + 12(c)  
destinationAddress = hex(base58.b58decode_int('1EHp4zm1T2yUyjEmW3H4qauTJiVEXan3Uf'))[2:-8]

# script operations (assembly language stack)
scriptOperationCheckSig_ac = 'ac'
scriptOperationDuplicate_76 = '76'
scriptOperationHash160_a9 = 'a9'
scriptOperationEqualVerify_88 = '88'

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

tx_obj = Tx.parse(BytesIO(bytes.fromhex(toSign)), testnet=False)
z = tx_obj.sig_hash(0)
derhex = private_key.sign(z).der().hex()
sechex = private_key.point.sec().hex()

SignatureScript = count_hex_bytes(derhex+oneAsVarInt) + derhex + oneAsVarInt + count_hex_bytes(sechex) + sechex

signedTransaction = (btcVersion + oneAsVarInt + # one since spending one output
                     previousTransactionId + previousTransactionIndex + 
                     count_hex_bytes(SignatureScript) + SignatureScript + sequence + 
                     oneAsVarInt + amountToSend + # one since sending single amount (no change address) extra sats are used for the fee
                     count_hex_bytes(PkScriptSend) + PkScriptSend + timelock)
expected2 = '01000000015e215bb23908c17d4a5843193240da0239de80780475e9af3aa587e3cda7ef8c000000006b4830450221008b1020af415df28930688ca8c70205737605f329efa10e9227ce6f2d93dcdf100220798e3dcd305aeff882b3fce1eeb53e40fb853cbad9685efe45383d4eb5516088012103ec6b306cf02e5e0d8b64574c85fd24b4cd43d85a92e9d36a837aa298245ec586fdffffff01dc020000000000001976a91491c794eb0d1b7760639b7c5a863521b09c31d4de88ac00000000' # https://blockstream.info/api/tx/f2f051f538810a205ddf2b1478d50f929dd079550af3cce20827a38dcb9ee9be/hex
expected = (urllib.request.urlopen("https://blockstream.info/api/tx/f2f051f538810a205ddf2b1478d50f929dd079550af3cce20827a38dcb9ee9be/hex").read()).decode("utf-8")

if(signedTransaction == expected or signedTransaction == expected2):
    print('MATCH!')
else:
    print('BAD NO MATCH')

h256 = hash256(bytes.fromhex(toSign + sigHashAll))
z = int.from_bytes(h256, 'big')
point = S256Point.parse(bytes.fromhex(sechex))
sig = Signature.parse(bytes.fromhex(derhex))

if(point.verify(z, sig) == True):
    print('Transaction is valid!')
else:
    print('Error: Not Valid Transaction')