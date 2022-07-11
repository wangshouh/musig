import { schnorr, utils, Point, CURVE } from "lib/@noble/secp256k1"

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



