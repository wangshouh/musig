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

interface Session {
    sessionId: Uint8Array,
    message: Uint8Array,
    pubKeyCombined: bigint,
    pkParity: boolean,
    ell: Uint8Array,
    idx: number,
    secretKey?: bigint,
    ownKeyParity?: boolean,
    secretNonce?: Uint8Array,
    nonce?: bigint,
    nonceParity?: boolean,
    commitment?: Uint8Array,
    combinedNonceParity?: boolean,
    partialSignature?: bigint
}


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

async function pubKeyCombine(pubKeys: Uint8Array[], pubKeyHash: Uint8Array) {
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

async function sessionInitialize(
    sessionId: Uint8Array,
    privateKey: bigint,
    message:Uint8Array,
    pubKeyCombined: bigint,
    pkParity: boolean,
    ell: Uint8Array,
    idx: number
) {
    const session: Session = {
        sessionId: sessionId,
        message: message,
        pubKeyCombined: pubKeyCombined,
        pkParity: pkParity,
        ell: ell,
        idx: idx,
    }
    const coefficient = await computeCoefficient(ell, idx);
    session.secretKey = utils.mod(privateKey * coefficient, CURVE.n);
    const privarePoint = Point.fromPrivateKey(privateKey);
    session.ownKeyParity = utils.hasEvenY(privarePoint);
    if (session.pkParity !== session.ownKeyParity) {
        session.secretKey = CURVE.n - session.secretKey;
    }
    const nonceData = utils.concatBytes(...
        [
            sessionId, message, utils.numTo32b(session.pubKeyCombined), utils.numTo32b(privateKey)
        ]
    );
    session.secretNonce = await utils.sha256(nonceData);
    const R = Point.fromPrivateKey(session.secretNonce);
    session.nonce = R.x;
    session.nonceParity = utils.hasEvenY(R);
    session.commitment = await utils.sha256(utils.numTo32b(session.nonce));
    
    return session;
}