"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("lib/@noble/secp256k1/index");
function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return bufView;
}
const MUSIG_TAG = index_1.utils.sha256(str2ab("MuSig coefficient"));
class PublicDataClass {
    constructor(pubKeys, message) {
        this.pubKeys = pubKeys;
        this.message = str2ab(message);
        this.pubKeyHash = this.computeEll();
        this.pkPoint = this.initPkPoint();
        this.pubKeyCombined = this.pkPoint.then(value => value.x);
        this.pubKeyParity = this.pkPoint.then(value => index_1.utils.hasEvenY(value));
    }
    async computeEll() {
        return index_1.utils.sha256(index_1.utils.concatBytes(...this.pubKeys));
    }
    async initPkPoint() {
        const pkCombined = await pubKeyCombine(this.pubKeys, await this.pubKeyHash);
        const pk = pkCombined.toAffine();
        return pk;
    }
}
async function computeCoefficient(ell, idx) {
    let idxBuf = new Uint8Array(4);
    const MUSIG_TAG_RESLOVE = await MUSIG_TAG;
    idxBuf[0] = idx;
    const data = index_1.utils.concatBytes(...[MUSIG_TAG_RESLOVE, MUSIG_TAG_RESLOVE, ell, idxBuf]);
    const hashData = await index_1.utils.sha256(data);
    const coefficient = index_1.utils.mod(index_1.utils.bytesToNumber(hashData));
    return coefficient;
}
async function pubKeyCombine(pubKeys, pubKeyHash) {
    let X = index_1.JacobianPoint.ZERO;
    for (let i = 0; i < pubKeys.length; i++) {
        const Xi = index_1.JacobianPoint.fromAffine(index_1.Point.fromHex(pubKeys[i]));
        const coefficient = await computeCoefficient(pubKeyHash, i);
        const summand = Xi.multiply(coefficient);
        if (X == index_1.JacobianPoint.ZERO) {
            X = summand;
        }
        else {
            X = X.add(summand);
        }
    }
    return X;
}
async function sessionInitialize(sessionId, privateKey, message, pubKeyCombined, pkParity, ell, idx) {
    const session = {
        sessionId: sessionId,
        message: message,
        pubKeyCombined: pubKeyCombined,
        pkParity: pkParity,
        ell: ell,
        idx: idx,
    };
    const coefficient = await computeCoefficient(ell, idx);
    session.secretKey = index_1.utils.mod(privateKey * coefficient, index_1.CURVE.n);
    const privarePoint = index_1.Point.fromPrivateKey(privateKey);
    session.ownKeyParity = index_1.utils.hasEvenY(privarePoint);
    if (session.pkParity !== session.ownKeyParity) {
        session.secretKey = index_1.CURVE.n - session.secretKey;
    }
    const nonceData = index_1.utils.concatBytes(...[
        sessionId, message, index_1.utils.numTo32b(session.pubKeyCombined), index_1.utils.numTo32b(privateKey)
    ]);
    session.secretNonce = await index_1.utils.sha256(nonceData);
    const R = index_1.Point.fromPrivateKey(session.secretNonce);
    session.nonce = R.x;
    session.nonceParity = index_1.utils.hasEvenY(R);
    session.commitment = await index_1.utils.sha256(index_1.utils.numTo32b(session.nonce));
    return session;
}
