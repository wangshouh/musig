# Typescript Musig

## Introduction

The project is based on schnorr signatures to implement the multi-signature part of [BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#Multisignatures_and_Threshold_Signatures), using the specific algorithm **musig**.The implementation of the algorithm refers to the implementation of Musig in [this repository](https://github.com/guggero/bip-schnorr).You can also read [this blog](https://blog.blockstream.com/en-musig-key-aggregation-schnorr-signatures/) or [paper](https://eprint.iacr.org/2018/068) to get more content about musig.

In order to improve the speed and reduce the size of the code, I used a lot of functions and classes from [noble-secp256k1](https://github.com/paulmillr/noble-secp256k1) in the implementation of musig.You can find these code in `src\@noble\secp256k1` path.

Warn: The underlying functions and classes from `noble-secp256k1` of this repository are cryptographically secure and audited, but the code implementation process is unaudited by my personal code writing, which may have vulnerabilities such as timing attacks so it is not recommended for production environments.

## Usage

You need to compile this code yourself, you can `tsc` command.

The sample code is as follows:
```javascript
import { utils, schnorr } from "./@noble/secp256k1/index.js"
import { SessionData, aggregateTranserData, partialSigCombine, partialSign } from "./index.js"

const pubKeys= [
    utils.hexToBytes('846f34fdb2345f4bf932cb4b7d278fb3af24f44224fb52ae551781c3a3cad68a'),
    utils.hexToBytes('50cebaa0efcb443f366240beb66504e14df69dc66aae829af80aa03ea25e1802'),
];

const privateKey1 = BigInt('0xadd2b25e2d356bec3770305391cbc80cab3a40057ad836bcb49ef3eed74a3fee')
const privateKey2 = BigInt('0xc5487234745cebddf6c6588995c16cebc029beed9f7affbb13d5cbe6c7a9e129')

const message = await utils.sha256('muSig is awesome!');

const session1 = new SessionData(0, privateKey1, pubKeys, message);
const session2 = new SessionData(1, privateKey2, pubKeys, message);

let sessions = [
    await session1.exportSession(),
    await session2.exportSession()
]

let aggregationTranser = aggregateTranserData(sessions);

let partialSignature1 = await partialSign(aggregationTranser, session1);
let partialSignature2 = await partialSign(aggregationTranser, session2);

let signature = await partialSigCombine(aggregationTranser, [partialSignature1, partialSignature2]);

let isValid = await schnorr.verify(signature, session1.message, utils.numTo32bStr(await session1.pubKeyCombined))

console.log(isValid)
```

To use this code under application, you need to complete 3 rounds of message exchange. In the first round of message exchange, each signer shoud exchange `publickey` and generate `pubKeys`. In the second round of message exchange, signer should exchange `session.exportSession()` and finish `partialSign` method. In the third round of message exchange, each signer should exchange `partialSignature`. After completing three rounds of information exchange, each signer can run the function `partialSigCombine` locally to obtain the final complete signature after obtaining partial signature information and each signer can run `schnorr.verify` to verify the signature.

During the use of this code, you may encounter this error:
```
Error: hexToBytes: received invalid unpadded hex63
```

This error occurs because the generated value of the random number does not satisfy certain conditions, I have not handled this error in the code, if you encounter this error, you can rerun the code to get a random number that meets the criteria.

If you can fix this error, please send a PR.