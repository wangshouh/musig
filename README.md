# Typescript Musig

The project is based on schnorr signatures to implement the multi-signature part of [BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#Multisignatures_and_Threshold_Signatures), using the specific algorithm **musig**.The implementation of the algorithm refers to the implementation of Musig in [this repository](https://github.com/guggero/bip-schnorr).You can also read [this blog](https://blog.blockstream.com/en-musig-key-aggregation-schnorr-signatures/) to get more content about musig.

In order to improve the speed and reduce the size of the code, I used a lot of functions and classes from [noble-secp256k1](https://github.com/paulmillr/noble-secp256k1) in the implementation of musig.You can find these code in `src\@noble\secp256k1` path.

Warn: The underlying functions and classes from `noble-secp256k1` of this repository are cryptographically secure and audited, but the code implementation process is unaudited by my personal code writing, which may have vulnerabilities such as timing attacks so it is not recommended for production environments.

