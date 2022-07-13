import { schnorr, utils, Point, CURVE, JacobianPoint } from "./@noble/secp256k1/index.js"

const MUSIG_TAG = utils.sha256("MuSig coefficient");

interface publicData {
    pubKeys: Uint8Array[],
    message: Uint8Array,
    pubKeyHash: Uint8Array,
    pubKeyCombined: bigint,
    pubKeyParity: boolean,
    commitments: Uint8Array[],
    nonces: bigint[],
    nonceCombined: bigint,
    partialSignatures: bigint[],
    signature: Uint8Array,
}

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

async function computeCoefficient(ell: Uint8Array, idx: number): Promise<bigint> {
    let idxBuf = new Uint8Array(4);
    const MUSIG_TAG_RESLOVE = await MUSIG_TAG;
    idxBuf[0] = idx;
    const data = utils.concatBytes(...[MUSIG_TAG_RESLOVE, MUSIG_TAG_RESLOVE, ell, idxBuf]);
    const hashData = await utils.sha256(data);
    const coefficient = utils.mod(utils.bytesToNumber(hashData));
    return coefficient;
}

async function pubKeyCombine(pubKeys: Uint8Array[], pubKeyHash: Uint8Array) {
    let X = JacobianPoint.ZERO;
    for (let i = 0; i < pubKeys.length; i++) {
        const Xi = JacobianPoint.fromAffine(Point.fromHex(pubKeys[i]));
        const coefficient = await computeCoefficient(pubKeyHash, i);
        const summand = Xi.multiply(coefficient);
        if (X == JacobianPoint.ZERO) {
            X = summand;
        } else {
            X = X.add(summand);
        }
    }
    return X;
}

export class PublicDataClass {
    pubKeys: Uint8Array[];
    message: Promise<Uint8Array>;
    pubKeyHash: Promise<Uint8Array>;
    pubKeyCombined: Promise<bigint>;
    pubKeyParity: Promise<boolean>;
    pkPoint: Promise<Point>;

    constructor(pubKeys: Uint8Array[], message: string) {
        this.pubKeys = pubKeys;
        this.message = utils.sha256(message);
        this.pubKeyHash = this.computeEll();
        this.pkPoint = this.initPkPoint();
        this.pubKeyCombined = this.pkPoint.then(value => value.x);
        this.pubKeyParity = this.pkPoint.then(value => utils.hasEvenY(value));
    }

    private async computeEll(): Promise<Uint8Array> {
        return utils.sha256(utils.concatBytes(...this.pubKeys))
    }

    private async initPkPoint() {
        const pkCombined = await pubKeyCombine(this.pubKeys, await this.pubKeyHash);
        const pk = pkCombined.toAffine();
        return pk
    }
}

export class SessionData extends PublicDataClass {
    idx: number;
    sessionId: Uint8Array;
    privateKey: bigint;
    secretKey: Promise<bigint>;
    secretNonce: Promise<Uint8Array>;
    nonce: Promise<bigint>;
    nonceParity: Promise<boolean>;
    commitment: Promise<Uint8Array>;


    constructor(idx:number, privateKey: bigint, pubKeys: Uint8Array[], message: string) {
        super(pubKeys, message);
        this.sessionId = utils.randomBytes(32);
        this.privateKey = privateKey;
        this.idx = idx;
        this.secretKey = this.secretKeyInit();
        this.secretNonce = this.secretNonceInit();
        this.nonce = this.RInit().then(point => point.x);
        this.nonceParity = this.RInit().then(point => utils.hasEvenY(point));
        this.commitment = this.nonce.then(value => utils.sha256(utils.numTo32b(value)));
    }

    private async secretKeyInit() {
        const ell = await super.pubKeyHash;
        const coefficient = await computeCoefficient(ell, this.idx);
        let secretKey = utils.mod(this.privateKey * coefficient, CURVE.n);
        const privarePoint = Point.fromPrivateKey(this.privateKey);
        const ownKeyParity = utils.hasEvenY(privarePoint);
        if (await super.pubKeyParity !== ownKeyParity) {
            secretKey = CURVE.n - secretKey;
        }
        return secretKey;
    }
    
    private async secretNonceInit() {
        const sessionId = this.sessionId;
        const message = await super.message;
        const pubKeyCombined = await super.pubKeyCombined;
        const privateKey = this.privateKey;
        const nonceData = utils.concatBytes(...
            [
                sessionId, message, utils.numTo32b(pubKeyCombined), utils.numTo32b(privateKey)
            ]
        );

        return utils.sha256(nonceData);
    }

    private async RInit() {
        const secretNonce = await this.secretNonce;
        return Point.fromPrivateKey(secretNonce); 
    }


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
