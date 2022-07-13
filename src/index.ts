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
    message: Uint8Array;
    pubKeyHash: Promise<Uint8Array>;
    pubKeyCombined: Promise<bigint>;
    pubKeyParity: Promise<boolean>;
    pkPoint: Promise<Point>;

    constructor(pubKeys: Uint8Array[], message: Uint8Array) {
        this.pubKeys = pubKeys;
        this.message = message;
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


    constructor(idx: number, privateKey: bigint, pubKeys: Uint8Array[], message: Uint8Array) {
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
        const ell = await this.pubKeyHash;
        const coefficient = await computeCoefficient(ell, this.idx);
        let secretKey = utils.mod(this.privateKey * coefficient, CURVE.n);
        const privarePoint = Point.fromPrivateKey(this.privateKey);
        const ownKeyParity = utils.hasEvenY(privarePoint);
        if (await this.pubKeyParity !== ownKeyParity) {
            secretKey = CURVE.n - secretKey;
        }
        return secretKey;
    }

    private async secretNonceInit() {
        const sessionId = this.sessionId;
        const message = await this.message;
        const pubKeyCombined = await this.pubKeyCombined;
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

export class aggregationData extends PublicDataClass {
    commitments: Uint8Array[];
    nonces: bigint[];
    nonceCombined: bigint;
    combinedNonceParity: boolean;
    partialSignatures: Promise<bigint[]>;

    constructor(sessions: SessionData[], pubKeys: Uint8Array[], message: Uint8Array) {
        super(pubKeys, message);
        this.commitments = this.initCommitments(sessions);
        this.nonces = this.initNonces(sessions);
        this.nonceCombined = this.initR().x;
        this.combinedNonceParity = utils.hasEvenY(this.initR());
        this.partialSignatures = this.partialSign(sessions);
    }

    private initCommitments(sessions: SessionData[]) {
        let commitments: Uint8Array[] = [];
        sessions.forEach(data => (data.commitment.then(value => commitments.push(value))));
        return commitments
    }

    private initNonces(sessions: SessionData[]) {
        let nonces: bigint[] = [];
        sessions.forEach(data => (data.nonce.then(value => nonces.push(value))));
        return nonces
    }

    private initR() {
        let R = JacobianPoint.fromAffine(Point.fromHex(this.nonces[0].toString(16)));
        for (let i = 1; i < this.nonces.length; i++) {
            const addR = JacobianPoint.fromAffine(Point.fromHex(this.nonces[i].toString(16)));
            R = R.add(addR);
        }
        const AffineR = R.toAffine();
        return AffineR;
    }

    private async partialSign(sessions: SessionData[]) {
        const partialSignatures: bigint[] = []
        const e = utils.bytesToNumber(await utils.taggedHash(
            'BIP0340/challenge',
            utils.numTo32b(this.nonceCombined),
            utils.numTo32b(await this.pubKeyCombined),
            this.message
        ));
        
        sessions.forEach(
            async session => {
                const sk = await session.secretKey;
                let k = utils.bytesToNumber(await session.secretNonce);
                if (await session.nonceParity !== this.combinedNonceParity) {
                    k = CURVE.n - k;
                }

                partialSignatures.push(utils.mod(sk * e + k, CURVE.n))
            }
        )
        
        return partialSignatures
    }
}

function nonceCombined(nonceCombined: any): Uint8Array {
    throw new Error("Function not implemented.");
}
