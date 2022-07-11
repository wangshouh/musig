import { schnorr, utils, Point, CURVE, JacobianPoint } from "lib/@noble/secp256k1/index"

function str2ab(str: String) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return bufView;
}

const MUSIG_TAG = await utils.sha256(str2ab("MuSig coefficient"));

async function computeEll(pubKeys: Uint8Array[]) {
    return utils.sha256(utils.concatBytes(...pubKeys))
}

async function computeCoefficient(ell: Uint8Array, idx: number): Promise<bigint> {
    let idxBuf = new Uint8Array(4);
    idxBuf[0] = idx
    const data = utils.concatBytes(...[MUSIG_TAG, MUSIG_TAG, ell, idxBuf]);
    const hashData = await utils.sha256(data);
    const coefficient = utils.mod(utils.bytesToNumber(hashData));
    return coefficient;
}

async function pubKeyCombine(pubKeys: Uint8Array[], pubKeyHash:Uint8Array ) {
    let X = null;
    for (let i = 0; i < pubKeys.length; i++) {
        const Xi = JacobianPoint.fromAffine(Point.fromHex(pubKeys[i]));
        const coefficient = await computeCoefficient(pubKeyHash, i);
        const summand = Xi.multiply(coefficient);
        if (X == null) {
            X = summand;
        } else {
            X = X.add(summand);
        }
    }
    return X;
}