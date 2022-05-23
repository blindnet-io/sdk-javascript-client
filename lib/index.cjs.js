'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

/**
 * https://bugs.webkit.org/show_bug.cgi?id=226547
 * Safari has a horrible bug where IDB requests can hang while the browser is starting up.
 * The only solution is to keep nudging it until it's awake.
 * This probably creates garbage, but garbage is better than totally failing.
 */
function idbReady() {
  var isSafari = !navigator.userAgentData && /Safari\//.test(navigator.userAgent) && !/Chrom(e|ium)\//.test(navigator.userAgent); // No point putting other browsers or older versions of Safari through this mess.

  if (!isSafari || !indexedDB.databases) return Promise.resolve();
  var intervalId;
  return new Promise(function (resolve) {
    var tryIdb = function tryIdb() {
      return indexedDB.databases().finally(resolve);
    };

    intervalId = setInterval(tryIdb, 100);
    tryIdb();
  }).finally(function () {
    return clearInterval(intervalId);
  });
}

function promisifyRequest(request) {
    return new Promise((resolve, reject) => {
        // @ts-ignore - file size hacks
        request.oncomplete = request.onsuccess = () => resolve(request.result);
        // @ts-ignore - file size hacks
        request.onabort = request.onerror = () => reject(request.error);
    });
}
function createStore(dbName, storeName) {
    const dbp = idbReady().then(() => {
        const request = indexedDB.open(dbName);
        request.onupgradeneeded = () => request.result.createObjectStore(storeName);
        return promisifyRequest(request);
    });
    return (txMode, callback) => dbp.then((db) => callback(db.transaction(storeName, txMode).objectStore(storeName)));
}
let defaultGetStoreFunc;
function defaultGetStore() {
    if (!defaultGetStoreFunc) {
        defaultGetStoreFunc = createStore('keyval-store', 'keyval');
    }
    return defaultGetStoreFunc;
}
/**
 * Get a value by its key.
 *
 * @param key
 * @param customStore Method to get a custom store. Use with caution (see the docs).
 */
function get(key, customStore = defaultGetStore()) {
    return customStore('readonly', (store) => promisifyRequest(store.get(key)));
}
/**
 * Set a value with a key.
 *
 * @param key
 * @param value
 * @param customStore Method to get a custom store. Use with caution (see the docs).
 */
function set(key, value, customStore = defaultGetStore()) {
    return customStore('readwrite', (store) => {
        store.put(value, key);
        return promisifyRequest(store.transaction);
    });
}
/**
 * Set multiple values at once. This is faster than calling set() multiple times.
 * It's also atomic – if one of the pairs can't be added, none will be added.
 *
 * @param entries Array of entries, where each entry is an array of `[key, value]`.
 * @param customStore Method to get a custom store. Use with caution (see the docs).
 */
function setMany(entries, customStore = defaultGetStore()) {
    return customStore('readwrite', (store) => {
        entries.forEach((entry) => store.put(entry[1], entry[0]));
        return promisifyRequest(store.transaction);
    });
}
/**
 * Get multiple values by their keys
 *
 * @param keys
 * @param customStore Method to get a custom store. Use with caution (see the docs).
 */
function getMany(keys, customStore = defaultGetStore()) {
    return customStore('readonly', (store) => Promise.all(keys.map((key) => promisifyRequest(store.get(key)))));
}
/**
 * Clear all values in the store.
 *
 * @param customStore Method to get a custom store. Use with caution (see the docs).
 */
function clear(customStore = defaultGetStore()) {
    return customStore('readwrite', (store) => {
        store.clear();
        return promisifyRequest(store.transaction);
    });
}

class IndexedDbKeyStore {
    constructor(dbName = 'blindnet', storeName = 'keys') {
        this.keys = ['private_enc', 'public_enc', 'private_sign', 'public_sign', 'derived'];
        this.keyLabels = ['eSK', 'ePK', 'sSK', 'sPK', 'aes'];
        this.storeKey = (type, key) => set(type, key, this.store);
        this.storeKeys = (eSK, ePK, sSK, sPK, aes) => setMany([['private_enc', eSK], ['public_enc', ePK], ['private_sign', sSK], ['public_sign', sPK], ['derived', aes]], this.store);
        this.getKey = (type) => get(type, this.store);
        this.getSignKey = (type) => get(type, this.store);
        this.getKeys = () => getMany(this.keys, this.store)
            .then(res => res.reduce((acc, cur, i) => (Object.assign(Object.assign({}, acc), { [this.keyLabels[i]]: cur })), {}));
        this.clear = () => clear(this.store);
        this.store = createStore(dbName, storeName);
    }
}

const isBrowser = typeof window === 'object';

function str2bin(str) {
    return new TextEncoder().encode(str);
}
function bin2str(ab) {
    return new TextDecoder().decode(ab);
}
function b64str2bin(b64str) {
    if (isBrowser)
        return Uint8Array.from(window.atob(b64str), c => c.charCodeAt(0));
    else
        return Buffer.from(b64str, 'base64');
}
function bin2b64str(arrayBuffer) {
    if (isBrowser) {
        const x = new Uint8Array(arrayBuffer);
        let str = '';
        for (let i = 0; i < x.length; i++) {
            str += String.fromCharCode(x[i]);
        }
        return window.btoa(str);
    }
    else
        return Buffer.from(arrayBuffer).toString('base64');
}
function concat(...buffers) {
    var res = new Uint8Array(buffers.reduce((acc, cur) => acc + cur.byteLength, 0));
    let offset = 0;
    buffers.forEach(buf => {
        res.set((buf instanceof ArrayBuffer) ? new Uint8Array(buf) : buf, offset);
        offset += buf.byteLength;
    });
    return res.buffer;
}
function to4Bytes(x) {
    return [x, (x << 8), (x << 16), (x << 24)].map(z => z >>> 24);
}
function from4Bytes(bytes) {
    return new Uint8Array(bytes).reduce((a, c, i) => a + c * Math.pow(2, (24 - i * 8)), 0);
}
function to2Bytes(x) {
    return [(x << 16), (x << 24)].map(z => z >>> 24);
}
function from2Bytes(bytes) {
    return new Uint8Array(bytes).reduce((a, c, i) => a + c * Math.pow(2, (8 - i * 8)), 0);
}
function bin2Hex(arr) {
    let s = '';
    const h = '0123456789ABCDEF';
    const x = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr;
    x.forEach((v) => { s += h[v >> 4] + h[v & 15]; });
    return s;
}
function hex2bin(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return new Uint8Array(bytes);
}
function mapError(f, e) {
    try {
        return f();
    }
    catch (_a) {
        throw e;
    }
}
function mapErrorAsync(f, e) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            return yield f();
        }
        catch (_a) {
            throw e;
        }
    });
}

class BlindnetServiceHttp {
    constructor(token, apiUrl, protocolVersion) {
        this.apiUrl = undefined;
        this.protocolVersion = undefined;
        this.token = undefined;
        this.registerUser = (ePK, sPK, enc_eSK, enc_sSK, salt, signedToken, signedEncPK) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/users`, {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    publicEncryptionKey: bin2b64str(ePK),
                    publicSigningKey: bin2b64str(sPK),
                    encryptedPrivateEncryptionKey: bin2b64str(enc_eSK),
                    encryptedPrivateSigningKey: bin2b64str(enc_sSK),
                    keyDerivationSalt: bin2b64str(salt),
                    signedJwt: bin2b64str(signedToken),
                    signedPublicEncryptionKey: bin2b64str(signedEncPK)
                })
            });
            return yield handleResponse(serverResp)(_ => undefined);
        });
        this.getUserData = () => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys/me`, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            });
            function mapping(data) {
                return {
                    type: 'UserFound',
                    userData: {
                        enc_PK: data.publicEncryptionKey,
                        e_enc_SK: data.encryptedPrivateEncryptionKey,
                        sign_PK: data.publicSigningKey,
                        e_sign_SK: data.encryptedPrivateSigningKey,
                        salt: data.keyDerivationSalt
                    }
                };
            }
            return yield handleResponse(serverResp, { type: 'UserNotFound' })(mapping);
        });
        this.getUsersPublicKey = (userId) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys/${userId}`, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            });
            return yield handleResponse(serverResp)(data => (Object.assign({}, data)));
        });
        this.getPublicKeys = (userIds) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys`, {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    userIds: userIds
                })
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.getGroupPublicKeys = (groupId) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys`, {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    groupId: groupId
                })
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.postEncryptedKeys = (encryptedKeys) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents`, {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify(encryptedKeys)
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.postEncryptedKeysForData = (encryptedKeys, documentID) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/${documentID}`, {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify(encryptedKeys)
            });
            return yield handleResponse(serverResp)(_ => undefined);
        });
        this.getDataKey = (dataId) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys/${dataId}`, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.getAllDataKeys = () => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys`, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.getDataKeys = (dataIds) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys`, {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    data_ids: dataIds
                })
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.getMetadata = (dataId) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/metadata?dataId=${dataId}`, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.updateUser = (esk, ssk, salt) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys/me`, {
                method: 'PUT',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    encryptedPrivateEncryptionKey: bin2b64str(esk),
                    encryptedPrivateSigningKey: bin2b64str(ssk),
                    keyDerivationSalt: bin2b64str(salt)
                })
            });
            return yield handleResponse(serverResp)(_ => undefined);
        });
        this.giveAccess = (userId, docKeys) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys/user/${userId}`, {
                method: 'PUT',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify(docKeys)
            });
            return yield handleResponse(serverResp)(_ => undefined);
        });
        this.initializeUpload = () => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/init-upload`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                mode: 'cors'
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.storeMetadata = (dataId, metadata) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/metadata`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                mode: 'cors',
                body: JSON.stringify({ dataID: dataId, metadata })
            });
            return yield handleResponse(serverResp)(_ => undefined);
        });
        this.getUploadBlockUrl = (dataId, chunkSize) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/get-upload-block-url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                mode: 'cors',
                body: JSON.stringify({ dataId, chunkSize })
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.finishUpload = (dataId, blockIds) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/finish-upload`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                mode: 'cors',
                body: JSON.stringify({ dataId, blockIds })
            });
            return yield handleResponse(serverResp)(_ => undefined);
        });
        this.getDownloadLink = (dataId) => __awaiter(this, void 0, void 0, function* () {
            const serverResp = yield fetch(`${this.apiUrl}/api/v${this.protocolVersion}/get-file-url/${dataId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                mode: 'cors'
            });
            return yield handleResponse(serverResp)(data => data);
        });
        this.updateToken = token => this.token = token;
        this.clearToken = () => this.token = undefined;
        this.token = token;
        this.apiUrl = apiUrl;
        this.protocolVersion = protocolVersion;
    }
}
const handleResponse = (resp, notFoundData) => (f) => __awaiter(void 0, void 0, void 0, function* () {
    switch (resp.status) {
        case 200: {
            const body = yield resp.json();
            return { type: 'Success', data: f(body) };
        }
        case 401:
            return { type: 'AuthenticationNeeded' };
        case 400: {
            if (notFoundData != undefined)
                return { type: 'Success', data: notFoundData };
            else
                return { type: 'Failed' };
        }
        default:
            return { type: 'Failed' };
    }
});

class AuthenticationError extends Error {
    constructor() {
        super('Authentication to blindnet failed. Please generate a valid token.');
        this.code = 'blindnet.authentication';
        this.name = 'AuthenticationError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class UserNotInitializedError extends Error {
    constructor(message) {
        super(message);
        this.code = 'blindnet.user_not_initialized';
        this.name = 'UserNotInitializedError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class SecretError extends Error {
    constructor() {
        super('Wrong secret provided.');
        this.code = 'blindnet.secret';
        this.name = 'SecretError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class BadFormatError extends Error {
    constructor(message) {
        super(message);
        this.code = 'blindnet.data_format';
        this.name = 'BadFormatError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class EncryptionError extends Error {
    constructor(message) {
        super(message);
        this.code = 'blindnet.encryption';
        this.name = 'EncryptionError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class BlindnetServiceError extends Error {
    constructor(message) {
        super(message);
        this.code = 'blindnet.service';
        this.name = 'BlindnetServiceError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class NotEncryptabeError extends Error {
    constructor(message) {
        super(message);
        this.code = 'blindnet.not_encryptable';
        this.name = 'NotEncryptabeError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class NoAccessError extends Error {
    constructor(message) {
        super(message);
        this.code = 7;
        this.name = 'NoAccessError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
class UserNotFoundError extends Error {
    constructor(message) {
        super(message);
        this.code = 8;
        this.name = 'UserNotFoundError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

var error = /*#__PURE__*/Object.freeze({
    __proto__: null,
    AuthenticationError: AuthenticationError,
    UserNotInitializedError: UserNotInitializedError,
    SecretError: SecretError,
    EncryptionError: EncryptionError,
    BlindnetServiceError: BlindnetServiceError,
    NotEncryptabeError: NotEncryptabeError,
    NoAccessError: NoAccessError,
    UserNotFoundError: UserNotFoundError,
    BadFormatError: BadFormatError
});

function unwrapExports (x) {
	return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
}

function createCommonjsModule(fn, module) {
	return module = { exports: {} }, fn(module, module.exports), module.exports;
}

function getCjsExportFromNamespace (n) {
	return n && n['default'] || n;
}

var empty = {};

var empty$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    'default': empty
});

var require$$0 = getCjsExportFromNamespace(empty$1);

var nobleEd25519 = createCommonjsModule(function (module, exports) {
/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.verify = exports.sign = exports.getPublicKey = exports.SignResult = exports.Signature = exports.Point = exports.ExtendedPoint = exports.CURVE = void 0;
const CURVE = {
    a: -1n,
    d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
    P: 2n ** 255n - 19n,
    n: 2n ** 252n + 27742317777372353535851937790883648493n,
    h: 8n,
    Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
};
exports.CURVE = CURVE;
const B32 = 32;
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n;
const INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n;
const ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838n;
const D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952n;
class ExtendedPoint {
    constructor(x, y, z, t) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.t = t;
    }
    static fromAffine(p) {
        if (!(p instanceof Point)) {
            throw new TypeError('ExtendedPoint#fromAffine: expected Point');
        }
        if (p.equals(Point.ZERO))
            return ExtendedPoint.ZERO;
        return new ExtendedPoint(p.x, p.y, 1n, mod(p.x * p.y));
    }
    static toAffineBatch(points) {
        const toInv = invertBatch(points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static normalizeZ(points) {
        return this.toAffineBatch(points).map(this.fromAffine);
    }
    static fromRistrettoHash(hash) {
        const r1 = bytes255ToNumberLE(hash.slice(0, B32));
        const R1 = this.calcElligatorRistrettoMap(r1);
        const r2 = bytes255ToNumberLE(hash.slice(B32, B32 * 2));
        const R2 = this.calcElligatorRistrettoMap(r2);
        return R1.add(R2);
    }
    static calcElligatorRistrettoMap(r0) {
        const { d } = CURVE;
        const r = mod(SQRT_M1 * r0 * r0);
        const Ns = mod((r + 1n) * ONE_MINUS_D_SQ);
        let c = -1n;
        const D = mod((c - d * r) * mod(r + d));
        let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
        let s_ = mod(s * r0);
        if (!edIsNegative(s_))
            s_ = mod(-s_);
        if (!Ns_D_is_sq)
            s = s_;
        if (!Ns_D_is_sq)
            c = r;
        const Nt = mod(c * (r - 1n) * D_MINUS_ONE_SQ - D);
        const s2 = s * s;
        const W0 = mod((s + s) * D);
        const W1 = mod(Nt * SQRT_AD_MINUS_ONE);
        const W2 = mod(1n - s2);
        const W3 = mod(1n + s2);
        return new ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
    }
    static fromRistrettoBytes(bytes) {
        const { a, d } = CURVE;
        const emsg = 'ExtendedPoint.fromRistrettoBytes: Cannot convert bytes to Ristretto Point';
        const s = bytes255ToNumberLE(bytes);
        if (!equalBytes(numberToBytesPadded(s, B32), bytes) || edIsNegative(s))
            throw new Error(emsg);
        const s2 = mod(s * s);
        const u1 = mod(1n + a * s2);
        const u2 = mod(1n - a * s2);
        const u1_2 = mod(u1 * u1);
        const u2_2 = mod(u2 * u2);
        const v = mod(a * d * u1_2 - u2_2);
        const { isValid, value: I } = invertSqrt(mod(v * u2_2));
        const Dx = mod(I * u2);
        const Dy = mod(I * Dx * v);
        let x = mod((s + s) * Dx);
        if (edIsNegative(x))
            x = mod(-x);
        const y = mod(u1 * Dy);
        const t = mod(x * y);
        if (!isValid || edIsNegative(t) || y === 0n)
            throw new Error(emsg);
        return new ExtendedPoint(x, y, 1n, t);
    }
    toRistrettoBytes() {
        let { x, y, z, t } = this;
        const u1 = mod((z + y) * (z - y));
        const u2 = mod(x * y);
        const { value: invsqrt } = invertSqrt(mod(u1 * u2 ** 2n));
        const D1 = mod(invsqrt * u1);
        const D2 = mod(invsqrt * u2);
        const zInv = mod(D1 * D2 * t);
        let D;
        if (edIsNegative(t * zInv)) {
            [x, y] = [mod(y * SQRT_M1), mod(x * SQRT_M1)];
            D = mod(D1 * INVSQRT_A_MINUS_D);
        }
        else {
            D = D2;
        }
        if (edIsNegative(x * zInv))
            y = mod(-y);
        let s = mod((z - y) * D);
        if (edIsNegative(s))
            s = mod(-s);
        return numberToBytesPadded(s, B32);
    }
    equals(other) {
        const a = this;
        const b = other;
        const [T1, T2, Z1, Z2] = [a.t, b.t, a.z, b.z];
        return mod(T1 * Z2) === mod(T2 * Z1);
    }
    negate() {
        return new ExtendedPoint(mod(-this.x), this.y, this.z, mod(-this.t));
    }
    double() {
        const X1 = this.x;
        const Y1 = this.y;
        const Z1 = this.z;
        const { a } = CURVE;
        const A = mod(X1 ** 2n);
        const B = mod(Y1 ** 2n);
        const C = mod(2n * Z1 ** 2n);
        const D = mod(a * A);
        const E = mod((X1 + Y1) ** 2n - A - B);
        const G = mod(D + B);
        const F = mod(G - C);
        const H = mod(D - B);
        const X3 = mod(E * F);
        const Y3 = mod(G * H);
        const T3 = mod(E * H);
        const Z3 = mod(F * G);
        return new ExtendedPoint(X3, Y3, Z3, T3);
    }
    add(other) {
        const X1 = this.x;
        const Y1 = this.y;
        const Z1 = this.z;
        const T1 = this.t;
        const X2 = other.x;
        const Y2 = other.y;
        const Z2 = other.z;
        const T2 = other.t;
        const A = mod((Y1 - X1) * (Y2 + X2));
        const B = mod((Y1 + X1) * (Y2 - X2));
        const F = mod(B - A);
        if (F === 0n) {
            return this.double();
        }
        const C = mod(Z1 * 2n * T2);
        const D = mod(T1 * 2n * Z2);
        const E = mod(D + C);
        const G = mod(B + A);
        const H = mod(D - C);
        const X3 = mod(E * F);
        const Y3 = mod(G * H);
        const T3 = mod(E * H);
        const Z3 = mod(F * G);
        return new ExtendedPoint(X3, Y3, Z3, T3);
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiplyUnsafe(scalar) {
        if (!isValidScalar(scalar))
            throw new TypeError('Point#multiply: expected number or bigint');
        let n = mod(BigInt(scalar), CURVE.n);
        if (n === 1n)
            return this;
        let p = ExtendedPoint.ZERO;
        let d = this;
        while (n > 0n) {
            if (n & 1n)
                p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }
    precomputeWindow(W) {
        const windows = 256 / W + 1;
        let points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
            base = p;
            points.push(base);
            for (let i = 1; i < 2 ** (W - 1); i++) {
                base = base.add(p);
                points.push(base);
            }
            p = base.double();
        }
        return points;
    }
    wNAF(n, affinePoint) {
        if (!affinePoint && this.equals(ExtendedPoint.BASE))
            affinePoint = Point.BASE;
        const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
        if (256 % W) {
            throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
        }
        let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
        if (!precomputes) {
            precomputes = this.precomputeWindow(W);
            if (affinePoint && W !== 1) {
                precomputes = ExtendedPoint.normalizeZ(precomputes);
                pointPrecomputes.set(affinePoint, precomputes);
            }
        }
        let p = ExtendedPoint.ZERO;
        let f = ExtendedPoint.ZERO;
        const windows = 256 / W + 1;
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += 1n;
            }
            if (wbits === 0) {
                f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
            }
            else {
                const cached = precomputes[offset + Math.abs(wbits) - 1];
                p = p.add(wbits < 0 ? cached.negate() : cached);
            }
        }
        return [p, f];
    }
    multiply(scalar, affinePoint) {
        if (!isValidScalar(scalar))
            throw new TypeError('Point#multiply: expected number or bigint');
        const n = mod(BigInt(scalar), CURVE.n);
        return ExtendedPoint.normalizeZ(this.wNAF(n, affinePoint))[0];
    }
    toAffine(invZ = invert(this.z)) {
        const x = mod(this.x * invZ);
        const y = mod(this.y * invZ);
        return new Point(x, y);
    }
}
exports.ExtendedPoint = ExtendedPoint;
ExtendedPoint.BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, 1n, mod(CURVE.Gx * CURVE.Gy));
ExtendedPoint.ZERO = new ExtendedPoint(0n, 1n, 1n, 0n);
const pointPrecomputes = new WeakMap();
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this._WINDOW_SIZE = windowSize;
        pointPrecomputes.delete(this);
    }
    static fromHex(hash) {
        const { d, P } = CURVE;
        const bytes = hash instanceof Uint8Array ? hash : hexToBytes(hash);
        if (bytes.length !== 32)
            throw new Error('Point.fromHex: expected 32 bytes');
        const last = bytes[31];
        const normedLast = last & ~0x80;
        const isLastByteOdd = (last & 0x80) !== 0;
        const normed = Uint8Array.from(Array.from(bytes.slice(0, 31)).concat(normedLast));
        const y = bytesToNumberLE(normed);
        if (y >= P)
            throw new Error('Point.fromHex expects hex <= Fp');
        const y2 = mod(y * y);
        const u = mod(y2 - 1n);
        const v = mod(d * y2 + 1n);
        let { isValid, value: x } = uvRatio(u, v);
        if (!isValid)
            throw new Error('Point.fromHex: invalid y coordinate');
        const isXOdd = (x & 1n) === 1n;
        if (isLastByteOdd !== isXOdd) {
            x = mod(-x);
        }
        return new Point(x, y);
    }
    static async fromPrivateKey(privateKey) {
        const privBytes = await exports.utils.sha512(normalizePrivateKey(privateKey));
        return Point.BASE.multiply(encodePrivate(privBytes));
    }
    toRawBytes() {
        const hex = numberToHex(this.y);
        const u8 = new Uint8Array(B32);
        for (let i = hex.length - 2, j = 0; j < B32 && i >= 0; i -= 2, j++) {
            u8[j] = Number.parseInt(hex[i] + hex[i + 1], 16);
        }
        const mask = this.x & 1n ? 0x80 : 0;
        u8[B32 - 1] |= mask;
        return u8;
    }
    toHex() {
        return bytesToHex(this.toRawBytes());
    }
    toX25519() {
        return mod((1n + this.y) * invert(1n - this.y));
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(mod(-this.x), this.y);
    }
    add(other) {
        return ExtendedPoint.fromAffine(this).add(ExtendedPoint.fromAffine(other)).toAffine();
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiply(scalar) {
        return ExtendedPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }
}
exports.Point = Point;
Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
Point.ZERO = new Point(0n, 1n);
class Signature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromHex(hex) {
        hex = ensureBytes(hex);
        const r = Point.fromHex(hex.slice(0, 32));
        const s = bytesToNumberLE(hex.slice(32));
        if (!isWithinCurveOrder(s))
            throw new Error('Signature.fromHex expects s <= CURVE.n');
        return new Signature(r, s);
    }
    toRawBytes() {
        const numberBytes = hexToBytes(numberToHex(this.s)).reverse();
        const sBytes = new Uint8Array(B32);
        sBytes.set(numberBytes);
        const res = new Uint8Array(B32 * 2);
        res.set(this.r.toRawBytes());
        res.set(sBytes, 32);
        return res;
    }
    toHex() {
        return bytesToHex(this.toRawBytes());
    }
}
exports.Signature = Signature;
exports.SignResult = Signature;
function concatBytes(...arrays) {
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function numberToHex(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function numberToBytesPadded(num, length = B32) {
    const hex = numberToHex(num).padStart(length * 2, '0');
    return hexToBytes(hex).reverse();
}
function edIsNegative(num) {
    return (mod(num) & 1n) === 1n;
}
function isValidScalar(num) {
    if (typeof num === 'bigint' && num > 0n)
        return true;
    if (typeof num === 'number' && num > 0 && Number.isSafeInteger(num))
        return true;
    return false;
}
function bytesToNumberLE(uint8a) {
    let value = 0n;
    for (let i = 0; i < uint8a.length; i++) {
        value += BigInt(uint8a[i]) << (8n * BigInt(i));
    }
    return value;
}
function bytes255ToNumberLE(bytes) {
    return mod(bytesToNumberLE(bytes) & (2n ** 255n - 1n));
}
function mod(a, b = CURVE.P) {
    const res = a % b;
    return res >= 0n ? res : b + res;
}
function invert(number, modulo = CURVE.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    let a = mod(number, modulo);
    let b = modulo;
    let [x, y, u, v] = [0n, 1n, 1n, 0n];
    while (a !== 0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        const n = y - v * q;
        [b, a] = [a, r];
        [x, y] = [u, v];
        [u, v] = [m, n];
    }
    const gcd = b;
    if (gcd !== 1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
function invertBatch(nums, n = CURVE.P) {
    const len = nums.length;
    const scratch = new Array(len);
    let acc = 1n;
    for (let i = 0; i < len; i++) {
        if (nums[i] === 0n)
            continue;
        scratch[i] = acc;
        acc = mod(acc * nums[i], n);
    }
    acc = invert(acc, n);
    for (let i = len - 1; i >= 0; i--) {
        if (nums[i] === 0n)
            continue;
        let tmp = mod(acc * nums[i], n);
        nums[i] = mod(acc * scratch[i], n);
        acc = tmp;
    }
    return nums;
}
function pow2(x, power) {
    const { P } = CURVE;
    let res = x;
    while (power-- > 0n) {
        res *= res;
        res %= P;
    }
    return res;
}
function pow_2_252_3(x) {
    const { P } = CURVE;
    const x2 = (x * x) % P;
    const b2 = (x2 * x) % P;
    const b4 = (pow2(b2, 2n) * b2) % P;
    const b5 = (pow2(b4, 1n) * x) % P;
    const b10 = (pow2(b5, 5n) * b5) % P;
    const b20 = (pow2(b10, 10n) * b10) % P;
    const b40 = (pow2(b20, 20n) * b20) % P;
    const b80 = (pow2(b40, 40n) * b40) % P;
    const b160 = (pow2(b80, 80n) * b80) % P;
    const b240 = (pow2(b160, 80n) * b80) % P;
    const b250 = (pow2(b240, 10n) * b10) % P;
    const pow_p_5_8 = (pow2(b250, 2n) * x) % P;
    return pow_p_5_8;
}
function uvRatio(u, v) {
    const v3 = mod(v * v * v);
    const v7 = mod(v3 * v3 * v);
    let x = mod(u * v3 * pow_2_252_3(u * v7));
    const vx2 = mod(v * x * x);
    const root1 = x;
    const root2 = mod(x * SQRT_M1);
    const useRoot1 = vx2 === u;
    const useRoot2 = vx2 === mod(-u);
    const noRoot = vx2 === mod(-u * SQRT_M1);
    if (useRoot1)
        x = root1;
    if (useRoot2 || noRoot)
        x = root2;
    if (edIsNegative(x))
        x = mod(-x);
    return { isValid: useRoot1 || useRoot2, value: x };
}
function invertSqrt(number) {
    return uvRatio(1n, number);
}
async function sha512ToNumberLE(...args) {
    const messageArray = concatBytes(...args);
    const hash = await exports.utils.sha512(messageArray);
    const value = bytesToNumberLE(hash);
    return mod(value, CURVE.n);
}
function keyPrefix(privateBytes) {
    return privateBytes.slice(B32);
}
function encodePrivate(privateBytes) {
    const last = B32 - 1;
    const head = privateBytes.slice(0, B32);
    head[0] &= 248;
    head[last] &= 127;
    head[last] |= 64;
    return mod(bytesToNumberLE(head), CURVE.n);
}
function equalBytes(b1, b2) {
    if (b1.length !== b2.length) {
        return false;
    }
    for (let i = 0; i < b1.length; i++) {
        if (b1[i] !== b2[i]) {
            return false;
        }
    }
    return true;
}
function ensureBytes(hash) {
    return hash instanceof Uint8Array ? hash : hexToBytes(hash);
}
function isWithinCurveOrder(num) {
    return 0 < num && num < CURVE.n;
}
function normalizePrivateKey(key) {
    let num;
    if (typeof key === 'bigint' || (typeof key === 'number' && Number.isSafeInteger(key))) {
        num = BigInt(key);
        if (num < 0n || num > 2n ** 256n)
            throw new Error('Expected 32 bytes of private key');
        key = num.toString(16).padStart(B32 * 2, '0');
    }
    if (typeof key === 'string') {
        if (key.length !== 64)
            throw new Error('Expected 32 bytes of private key');
        return hexToBytes(key);
    }
    else if (key instanceof Uint8Array) {
        if (key.length !== 32)
            throw new Error('Expected 32 bytes of private key');
        return key;
    }
    else {
        throw new TypeError('Expected valid private key');
    }
}
async function getPublicKey(privateKey) {
    const key = await Point.fromPrivateKey(privateKey);
    return typeof privateKey === 'string' ? key.toHex() : key.toRawBytes();
}
exports.getPublicKey = getPublicKey;
async function sign(hash, privateKey) {
    const privBytes = await exports.utils.sha512(normalizePrivateKey(privateKey));
    const p = encodePrivate(privBytes);
    const P = Point.BASE.multiply(p);
    const msg = ensureBytes(hash);
    const r = await sha512ToNumberLE(keyPrefix(privBytes), msg);
    const R = Point.BASE.multiply(r);
    const h = await sha512ToNumberLE(R.toRawBytes(), P.toRawBytes(), msg);
    const S = mod(r + h * p, CURVE.n);
    const sig = new Signature(R, S);
    return typeof hash === 'string' ? sig.toHex() : sig.toRawBytes();
}
exports.sign = sign;
async function verify(signature, hash, publicKey) {
    hash = ensureBytes(hash);
    if (!(publicKey instanceof Point))
        publicKey = Point.fromHex(publicKey);
    if (!(signature instanceof Signature))
        signature = Signature.fromHex(signature);
    const hs = await sha512ToNumberLE(signature.r.toRawBytes(), publicKey.toRawBytes(), hash);
    const Ph = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(hs);
    const Gs = ExtendedPoint.BASE.multiply(signature.s);
    const RPh = ExtendedPoint.fromAffine(signature.r).add(Ph);
    return RPh.subtract(Gs).multiplyUnsafe(8n).equals(ExtendedPoint.ZERO);
}
exports.verify = verify;
Point.BASE._setWindowSize(8);
exports.utils = {
    TORSION_SUBGROUP: [
        '0100000000000000000000000000000000000000000000000000000000000000',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        '0000000000000000000000000000000000000000000000000000000000000080',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    ],
    randomPrivateKey: (bytesLength = 32) => {
        if (typeof self == 'object' && 'crypto' in self) {
            return self.crypto.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (typeof process === 'object' && 'node' in process.versions) {
            const { randomBytes } = require$$0;
            return new Uint8Array(randomBytes(bytesLength).buffer);
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    sha512: async (message) => {
        if (typeof self == 'object' && 'crypto' in self) {
            const buffer = await self.crypto.subtle.digest('SHA-512', message.buffer);
            return new Uint8Array(buffer);
        }
        else if (typeof process === 'object' && 'node' in process.versions) {
            const { createHash } = require$$0;
            const hash = createHash('sha512');
            hash.update(message);
            return Uint8Array.from(hash.digest());
        }
        else {
            throw new Error("The environment doesn't have sha512 function");
        }
    },
    precompute(windowSize = 8, point = Point.BASE) {
        const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(1n);
        return cached;
    },
};
});

unwrapExports(nobleEd25519);
var nobleEd25519_1 = nobleEd25519.utils;
nobleEd25519.verify;
var nobleEd25519_3 = nobleEd25519.sign;
var nobleEd25519_4 = nobleEd25519.getPublicKey;
nobleEd25519.SignResult;
nobleEd25519.Signature;
nobleEd25519.Point;
nobleEd25519.ExtendedPoint;
nobleEd25519.CURVE;

function deriveIv(iv, i) {
    return __awaiter(this, void 0, void 0, function* () {
        const hash = yield crypto.subtle.digest('SHA-256', concat(iv, Uint8Array.from([i])));
        return new Uint8Array(hash).slice(0, 12);
    });
}
function deriveAESKey(password, salt, extractable = false) {
    return __awaiter(this, void 0, void 0, function* () {
        const s = typeof salt === 'string' ? b64str2bin(salt) : salt;
        const passKey = yield crypto.subtle.importKey("raw", str2bin(password), "PBKDF2", false, ["deriveKey"]);
        const aesKey = yield crypto.subtle.deriveKey({
            name: "PBKDF2",
            salt: s,
            iterations: 100000,
            hash: "SHA-256",
        }, passKey, { name: "AES-GCM", length: 256 }, extractable, ["decrypt", "encrypt", "wrapKey", "unwrapKey"]);
        return aesKey;
    });
}
function deriveSecrets(seed, salt = new Uint8Array([241, 211, 153, 239, 17, 34, 5, 112, 167, 218, 57, 131, 99, 29, 243, 84])) {
    return __awaiter(this, void 0, void 0, function* () {
        const s = (seed.length === 0 || seed == undefined) ? 'seed' : seed;
        const passKey = yield crypto.subtle.importKey("raw", str2bin(s), "PBKDF2", false, ["deriveBits"]);
        const derivedBits = yield crypto.subtle.deriveBits({
            "name": "PBKDF2",
            salt: salt,
            "iterations": 64206,
            "hash": "SHA-256"
        }, passKey, 512);
        return { secret1: new Uint8Array(derivedBits, 0, 32), secret2: new Uint8Array(derivedBits, 32, 32) };
    });
}
function generateRandomAESKey() {
    return __awaiter(this, void 0, void 0, function* () {
        const key = yield crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        return key;
    });
}
function generateRandomRSAKeyPair() {
    return __awaiter(this, void 0, void 0, function* () {
        const keyPair = yield crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
        return keyPair;
    });
}
function generateRandomSigningKeyPair() {
    return __awaiter(this, void 0, void 0, function* () {
        const privateKey = nobleEd25519_1.randomPrivateKey();
        const publicKey = yield nobleEd25519_4(privateKey);
        return { privateKey, publicKey };
    });
}
function sign(toSign, secretKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const ts = typeof toSign === 'string' ? str2bin(toSign) : toSign;
        return nobleEd25519_3(new Uint8Array(ts), secretKey);
    });
}
function importPublicKey(publicKey) {
    return crypto.subtle.importKey("jwk", publicKey, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["wrapKey", "encrypt"]);
}
function exportPublicKey(publicKey) {
    return crypto.subtle.exportKey("jwk", publicKey);
}
function wrapSecretKey(secretKey, aesKey, iv) {
    return __awaiter(this, void 0, void 0, function* () {
        const wrappedSk = yield crypto.subtle.wrapKey("jwk", secretKey, aesKey, { name: "AES-GCM", iv });
        return wrappedSk;
    });
}
function unwrapSecretKey(wrappedSk, aesKey, iv) {
    return __awaiter(this, void 0, void 0, function* () {
        const wsk = typeof wrappedSk === 'string' ? b64str2bin(wrappedSk) : wrappedSk;
        return crypto.subtle.unwrapKey("jwk", wsk, aesKey, { name: "AES-GCM", iv: iv }, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt", "unwrapKey"]);
    });
}
function wrapAESKey(aesKey, wrappingKey) {
    return crypto.subtle.wrapKey("jwk", aesKey, wrappingKey, { name: "RSA-OAEP" });
}
function unwrapAESKey(wrappedKey, secretKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const wk = typeof wrappedKey === 'string' ? b64str2bin(wrappedKey) : wrappedKey;
        const key = yield crypto.subtle.unwrapKey("jwk", wk, secretKey, { name: "RSA-OAEP" }, { name: "AES-GCM", length: 256 }, true, ['encrypt', 'decrypt']);
        return key;
    });
}
function encryptData(aesKey, iv, data) {
    return __awaiter(this, void 0, void 0, function* () {
        const encrypted = yield crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, data);
        return encrypted;
    });
}
function decryptData(aesKey, iv, encrypted) {
    return __awaiter(this, void 0, void 0, function* () {
        const decrypted = crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encrypted);
        return decrypted;
    });
}

class AzureStorageService {
    constructor() {
        this.uploadBlock = (url, authorization, date, body) => __awaiter(this, void 0, void 0, function* () {
            const storageResp = yield fetch(url, {
                method: 'PUT',
                headers: {
                    'Authorization': authorization,
                    'x-ms-date': date,
                    'x-ms-blob-type': 'BlockBlob',
                    'x-ms-version': '2021-04-10',
                    "Content-Type": "application/octet-stream",
                },
                mode: 'cors',
                body: body
            });
            switch (storageResp.status) {
                case 201: {
                    return { type: 'Success', data: undefined };
                }
                default:
                    return { type: 'Failed' };
            }
        });
        this.downloadBlob = (url, authorization, date) => __awaiter(this, void 0, void 0, function* () {
            const storageResp = yield fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': authorization,
                    'x-ms-date': date,
                    'x-ms-version': '2021-04-10',
                },
                mode: 'cors'
            });
            switch (storageResp.status) {
                case 200: {
                    return { type: 'Success', data: storageResp.body };
                }
                default:
                    return { type: 'Failed' };
            }
        });
    }
}

function validateServiceResponse(resp, errorMsg, isValid = _ => true) {
    if (resp.type === 'AuthenticationNeeded')
        throw new AuthenticationError();
    else if (resp.type === 'Failed' || !isValid(resp.data))
        throw new BlindnetServiceError(errorMsg);
    else
        return resp.data;
}
class CaptureBuilder {
    constructor(data, service, storageService) {
        this.data = data;
        this.metadata = {};
        this.service = service;
        this.storageService = storageService;
    }
    withMetadata(metadata) {
        this.metadata = metadata;
        return this;
    }
    forUser(userId) {
        this.userIds = [userId];
        return this;
    }
    forUsers(userIds) {
        this.userIds = userIds;
        return this;
    }
    forGroup(groupId) {
        this.groupId = groupId;
        return this;
    }
    encrypt() {
        return __awaiter(this, void 0, void 0, function* () {
            const { data, metadata } = this;
            if (data === null || data === undefined)
                throw new BadFormatError('Data can\'t be undefined or null');
            if (typeof metadata !== 'object')
                throw new BadFormatError('Metadata has to be an object');
            let dataBin, dataType;
            if (typeof data === 'string') {
                dataBin = str2bin(data);
                dataType = { type: 'String' };
            }
            else if (data instanceof File) {
                dataBin = yield data.arrayBuffer();
                dataType = { type: 'File', name: data.name };
            }
            else if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
                dataBin = data;
                dataType = { type: 'Binary' };
            }
            else if (typeof data === 'object') {
                dataBin = mapError(() => str2bin(JSON.stringify(data)), new BadFormatError('Data in bad format'));
                dataType = { type: 'Json' };
            }
            else
                throw new BadFormatError('Encryption of provided data format is not supported');
            const dataTypeBin = str2bin(JSON.stringify(dataType));
            const dataTypeLenBytes = to2Bytes(dataTypeBin.byteLength);
            const metadataBin = str2bin(JSON.stringify(metadata));
            const metadataLenBytes = to4Bytes(metadataBin.byteLength);
            let resp;
            if (this.userIds != null && Object.prototype.toString.call(this.userIds) === '[object Array]')
                resp = yield this.service.getPublicKeys(this.userIds);
            else if (this.groupId != null && typeof this.groupId === 'string')
                resp = yield this.service.getGroupPublicKeys(this.groupId);
            else
                throw new NotEncryptabeError('You must specify a list of users or a group to encrypt the data for');
            const users = validateServiceResponse(resp, 'Fetching public keys failed');
            if (users.length == 0)
                throw new NotEncryptabeError('Selected users not found');
            const toEncrypt = concat(new Uint8Array(dataTypeLenBytes), new Uint8Array(metadataLenBytes), dataTypeBin, metadataBin, dataBin);
            const dataKey = yield mapErrorAsync(() => generateRandomAESKey(), new EncryptionError("Could not generate key"));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = yield mapErrorAsync(() => encryptData(dataKey, iv, toEncrypt), new EncryptionError("Could not encrypt data"));
            const encryptedUserKeys = yield Promise.all(users.map((user) => __awaiter(this, void 0, void 0, function* () {
                const PK = yield mapErrorAsync(() => importPublicKey(JSON.parse(bin2str(b64str2bin(user.publicEncryptionKey)))), new EncryptionError("Public key in wrong format"));
                const encryptedDataKey = yield mapErrorAsync(() => wrapAESKey(dataKey, PK), new EncryptionError("Could not encrypt data key"));
                return { userID: user.userID, encryptedSymmetricKey: bin2b64str(encryptedDataKey) };
            })));
            const postKeysResp = yield this.service.postEncryptedKeys(encryptedUserKeys);
            const dataId = validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys');
            const encryptedData = concat(str2bin(dataId), iv.buffer, encrypted);
            return { dataId, encryptedData };
        });
    }
    store() {
        return __awaiter(this, void 0, void 0, function* () {
            const { data, metadata } = this;
            if (!(data instanceof File))
                throw new BadFormatError('Only files are supported');
            if (typeof metadata !== 'object')
                throw new BadFormatError('Metadata has to be an object');
            const dataKey = yield mapErrorAsync(() => generateRandomAESKey(), new EncryptionError("Could not generate key"));
            let getPublicKeysResp;
            if (this.userIds != null && Object.prototype.toString.call(this.userIds) === '[object Array]')
                getPublicKeysResp = yield this.service.getPublicKeys(this.userIds);
            else if (this.groupId != null && typeof this.groupId === 'string')
                getPublicKeysResp = yield this.service.getGroupPublicKeys(this.groupId);
            else
                throw new NotEncryptabeError('You must specify a list of users or a group to encrypt the data for');
            const users = validateServiceResponse(getPublicKeysResp, 'Fetching public keys failed');
            const initUploadResp = yield this.service.initializeUpload();
            const { dataId } = validateServiceResponse(initUploadResp, 'Upload initialization failed');
            const encryptedUserKeys = yield Promise.all(users.map((user) => __awaiter(this, void 0, void 0, function* () {
                const PK = yield mapErrorAsync(() => importPublicKey(JSON.parse(bin2str(b64str2bin(user.publicEncryptionKey)))), new EncryptionError("Public key in wrong format"));
                const encryptedDataKey = yield mapErrorAsync(() => wrapAESKey(dataKey, PK), new EncryptionError("Could not encrypt data key"));
                return { userID: user.userID, encryptedSymmetricKey: bin2b64str(encryptedDataKey) };
            })));
            const postKeysResp = yield this.service.postEncryptedKeysForData(encryptedUserKeys, dataId);
            validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys');
            const dataType = { type: 'File', name: data.name, size: data.size };
            const dataTypeBin = str2bin(JSON.stringify(dataType));
            const dataTypeLenBytes = to2Bytes(dataTypeBin.byteLength);
            const metadataBin = str2bin(JSON.stringify(metadata));
            const toEncrypt = concat(new Uint8Array(dataTypeLenBytes), dataTypeBin, metadataBin);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedMetadata = yield mapErrorAsync(() => encryptData(dataKey, iv, toEncrypt), new EncryptionError("Could not encrypt data"))
                .then(enc => concat(iv.buffer, enc));
            const storeMetadataResp = yield this.service.storeMetadata(dataId, bin2b64str(encryptedMetadata));
            validateServiceResponse(storeMetadataResp, 'Could not store metadata');
            const blockSize = 4000000;
            function uploadBlocks(i, offset, dataId, file, blockIds, service, storageService) {
                return __awaiter(this, void 0, void 0, function* () {
                    if (offset >= file.size)
                        return blockIds;
                    const filePart = yield file.slice(offset, offset + blockSize).arrayBuffer();
                    const partIv = yield deriveIv(iv, i);
                    const encryptedPart = yield mapErrorAsync(() => encryptData(dataKey, partIv, filePart), new EncryptionError("Could not encrypt data"));
                    const uploadBlockUrlResp = yield service.getUploadBlockUrl(dataId, encryptedPart.byteLength);
                    const { blockId, date, authorization, url } = validateServiceResponse(uploadBlockUrlResp, 'Could not get upload url');
                    const uploadRes = yield storageService.uploadBlock(url, authorization, date, encryptedPart);
                    validateServiceResponse(uploadRes, 'Could not upload data part');
                    return uploadBlocks(i + 1, offset + blockSize, dataId, file, [...blockIds, blockId], service, storageService);
                });
            }
            const blockIds = yield uploadBlocks(0, 0, dataId, data, [], this.service, this.storageService);
            const finishUploadResp = yield this.service.finishUpload(dataId, blockIds);
            validateServiceResponse(finishUploadResp, 'Could not get upload url');
            return { dataId };
        });
    }
}
class Blindnet {
    constructor(service, storageService, keyStore) {
        this.service = service;
        this.storageService = storageService;
        this.keyStore = keyStore;
    }
    static testBrowser() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const aesKeyP = generateRandomAESKey();
                if (!(aesKeyP instanceof Promise))
                    return false;
                const aesKey = yield aesKeyP;
                const rsaKeyPair = yield generateRandomRSAKeyPair();
                const eccKeyPair = yield generateRandomSigningKeyPair();
                const keyStore = new IndexedDbKeyStore('blindnet_test');
                yield keyStore.clear();
                yield keyStore.storeKey('test_key', aesKey);
                yield keyStore.storeKeys(rsaKeyPair.privateKey, rsaKeyPair.publicKey, eccKeyPair.privateKey, eccKeyPair.publicKey, aesKey);
                const key = yield keyStore.getKey('test_key');
                if (!(key instanceof CryptoKey))
                    return false;
                const keys = yield keyStore.getKeys();
                if (!(keys.eSK instanceof CryptoKey) ||
                    !(keys.ePK instanceof CryptoKey) ||
                    !(keys.sSK instanceof Uint8Array) ||
                    !(keys.sPK instanceof Uint8Array) ||
                    !(keys.aes instanceof CryptoKey))
                    return false;
                yield keyStore.clear();
            }
            catch (e) {
                console.error(e);
                return false;
            }
            return true;
        });
    }
    static initCustomKeyStore(token, keyStore, apiUrl = Blindnet.apiUrl) {
        const service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion);
        const storageService = new AzureStorageService();
        return new Blindnet(service, storageService, keyStore);
    }
    static init(token, apiUrl = Blindnet.apiUrl) {
        const service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion);
        const storageService = new AzureStorageService();
        const keyStore = new IndexedDbKeyStore();
        return new Blindnet(service, storageService, keyStore);
    }
    static disconnect() {
        return __awaiter(this, void 0, void 0, function* () {
            yield (new IndexedDbKeyStore()).clear();
        });
    }
    disconnect() {
        return __awaiter(this, void 0, void 0, function* () {
            this.service.clearToken();
            yield this.keyStore.clear();
        });
    }
    refreshToken(token) {
        this.service.updateToken(token);
    }
    static deriveSecrets(seed) {
        return __awaiter(this, void 0, void 0, function* () {
            const { secret1, secret2 } = yield deriveSecrets(seed);
            const blindnetSecret = bin2b64str(secret1);
            const appSecret = bin2b64str(secret2);
            return { blindnetSecret, appSecret };
        });
    }
    getKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = yield mapErrorAsync(() => this.keyStore.getKeys(), new UserNotInitializedError('Keys not initialized'));
            if (Object.values(keys).length === 0 || Object.values(keys).some(x => x == undefined))
                throw new UserNotInitializedError('Keys not initialized');
            return keys;
        });
    }
    connect(secret) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.keyStore.clear();
            const resp = yield this.service.getUserData();
            const getUserResp = validateServiceResponse(resp, 'Fetching user data failed');
            switch (getUserResp.type) {
                case 'UserNotFound': {
                    const { privateKey: eSK, publicKey: ePK } = yield generateRandomRSAKeyPair();
                    const { privateKey: sSK, publicKey: sPK } = yield generateRandomSigningKeyPair();
                    const encPKexp = str2bin(JSON.stringify(yield exportPublicKey(ePK)));
                    const signedToken = yield sign(this.service.token, sSK);
                    const signedEncPK = yield sign(encPKexp, sSK);
                    const salt = crypto.getRandomValues(new Uint8Array(16));
                    const aesKey = yield deriveAESKey(secret, salt);
                    const enc_eSK = yield wrapSecretKey(eSK, aesKey, new Uint8Array(12));
                    const enc_sSK = yield encryptData(aesKey, new Uint8Array(12).map(_ => 1), concat(sSK, sPK));
                    const resp = yield this.service.registerUser(encPKexp, sPK, enc_eSK, enc_sSK, salt, signedToken, signedEncPK);
                    validateServiceResponse(resp, 'User could not be registered');
                    yield this.keyStore.storeKeys(eSK, ePK, sSK, sPK, aesKey);
                    return undefined;
                }
                case 'UserFound': {
                    const { enc_PK, e_enc_SK, sign_PK, e_sign_SK, salt } = getUserResp.userData;
                    const ePK = yield importPublicKey(JSON.parse(bin2str(b64str2bin(enc_PK))));
                    const aesKey = yield deriveAESKey(secret, salt);
                    const eSK = yield mapErrorAsync(() => unwrapSecretKey(e_enc_SK, aesKey, new Uint8Array(12)), new SecretError());
                    const sSK = yield mapErrorAsync(() => decryptData(aesKey, new Uint8Array(12).map(_ => 1), b64str2bin(e_sign_SK)), new SecretError());
                    yield this.keyStore.storeKeys(eSK, ePK, new Uint8Array(sSK).slice(0, 32), b64str2bin(sign_PK), aesKey);
                    return undefined;
                }
            }
        });
    }
    capture(data) {
        return new CaptureBuilder(data, this.service, this.storageService);
    }
    retrieve(dataId) {
        return __awaiter(this, void 0, void 0, function* () {
            const { eSK } = yield this.getKeys();
            const encryptedDataKeyresp = yield this.service.getDataKey(dataId);
            const encryptedDataKey = validateServiceResponse(encryptedDataKeyresp, `Fetching data key failed for data with id ${dataId}`);
            const dataKey = yield mapErrorAsync(() => unwrapAESKey(b64str2bin(encryptedDataKey), eSK), new EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`));
            const encryptedMetadataResp = yield this.service.getMetadata(dataId);
            const encryptedMetadataB64 = validateServiceResponse(encryptedMetadataResp, `Fetching metadata failed for id ${dataId}`);
            const encMetaBin = b64str2bin(encryptedMetadataB64);
            const iv = encMetaBin.slice(0, 12);
            const decrypted = yield mapErrorAsync(() => decryptData(dataKey, iv, encMetaBin.slice(12)), new EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`));
            let metadata, dataType;
            try {
                const dataTypeLen = from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))));
                const dataTypeBytes = decrypted.slice(2, 2 + dataTypeLen);
                dataType = JSON.parse(bin2str(dataTypeBytes));
                const metadataBytes = decrypted.slice(2 + dataTypeLen);
                metadata = JSON.parse(bin2str(metadataBytes));
            }
            catch (_a) {
                throw new BadFormatError("Bad data provided");
            }
            const getDownloadLinkResp = yield this.service.getDownloadLink(dataId);
            const { date, authorization, url } = validateServiceResponse(getDownloadLinkResp, 'Could not get download link');
            const getBlobResp = yield this.storageService.downloadBlob(url, authorization, date);
            const encrytedFileStream = validateServiceResponse(getBlobResp, 'Could not download file');
            const blockSize = 4000000 + 16;
            const encryptedFileStreamReader = encrytedFileStream.getReader();
            const chunkedStream = new ReadableStream({
                start(ctrl) {
                    let leftOverBytes = new Uint8Array();
                    function pump() {
                        encryptedFileStreamReader.read().then(readRes => {
                            const { done, value: chunk } = readRes;
                            if (done) {
                                if (leftOverBytes.length > 0) {
                                    ctrl.enqueue(leftOverBytes.slice(0, leftOverBytes.length));
                                }
                                ctrl.close();
                                return undefined;
                            }
                            if (leftOverBytes.length + chunk.length === blockSize) {
                                var newChunk = new Uint8Array(blockSize);
                                newChunk.set(leftOverBytes, 0);
                                newChunk.set(chunk, leftOverBytes.length);
                                ctrl.enqueue(newChunk);
                                leftOverBytes = new Uint8Array();
                            }
                            else if (leftOverBytes.length + chunk.length < blockSize) {
                                var newChunk = new Uint8Array(leftOverBytes.length + chunk.length);
                                newChunk.set(leftOverBytes, 0);
                                newChunk.set(chunk, leftOverBytes.length);
                                leftOverBytes = new Uint8Array(newChunk);
                            }
                            else if (leftOverBytes.length + chunk.length > blockSize) {
                                var newChunk = new Uint8Array(blockSize);
                                newChunk.set(leftOverBytes, 0);
                                newChunk.set(chunk.slice(0, blockSize - leftOverBytes.length), leftOverBytes.length);
                                ctrl.enqueue(newChunk);
                                const slicedChunk = chunk.slice(blockSize - leftOverBytes.length);
                                function p(v) {
                                    if (v.length < blockSize)
                                        leftOverBytes = new Uint8Array(v);
                                    else {
                                        const chunk = v.slice(0, blockSize);
                                        ctrl.enqueue(chunk);
                                        p(v.slice(blockSize));
                                    }
                                }
                                p(slicedChunk);
                            }
                            pump();
                        });
                    }
                    pump();
                }
            });
            const chunkedStreamReader = chunkedStream.getReader();
            const decryptedStream = new ReadableStream({
                start(ctrl) {
                    function pump(i) {
                        chunkedStreamReader.read().then((res) => __awaiter(this, void 0, void 0, function* () {
                            const { done, value } = res;
                            if (done || value === undefined) {
                                ctrl.close();
                                return undefined;
                            }
                            const partIv = yield deriveIv(iv, i);
                            const decrypted = yield decryptData(dataKey, partIv, value);
                            ctrl.enqueue(new Uint8Array(decrypted));
                            return pump(i + 1);
                        }));
                    }
                    return pump(0);
                }
            });
            return { data: decryptedStream, metadata, dataType };
        });
    }
    decrypt(encryptedData) {
        return __awaiter(this, void 0, void 0, function* () {
            const { eSK } = yield this.getKeys();
            const dataId = mapError(() => bin2str(encryptedData.slice(0, 36)), new BadFormatError("Bad data provided"));
            if (dataId.length !== 36)
                throw new BadFormatError("Bad data provided");
            const resp = yield this.service.getDataKey(dataId);
            const encryptedDataKey = validateServiceResponse(resp, `Fetching data key failed for data with id ${dataId}`);
            const dataKey = yield mapErrorAsync(() => unwrapAESKey(b64str2bin(encryptedDataKey), eSK), new EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`));
            const decrypted = yield mapErrorAsync(() => decryptData(dataKey, encryptedData.slice(36, 48), encryptedData.slice(48)), new EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`));
            let dataBytes, metadata, dataType;
            try {
                const dataTypeLen = from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))));
                const dataTypeBytes = decrypted.slice(6, 6 + dataTypeLen);
                dataType = JSON.parse(bin2str(dataTypeBytes));
                const metadataLen = from4Bytes(Array.from(new Uint8Array(decrypted.slice(2, 6))));
                const metadataBytes = decrypted.slice(6 + dataTypeLen, 6 + dataTypeLen + metadataLen);
                metadata = JSON.parse(bin2str(metadataBytes));
                dataBytes = decrypted.slice(6 + dataTypeLen + metadataLen);
            }
            catch (_a) {
                throw new BadFormatError("Bad data provided");
            }
            switch (dataType.type) {
                case 'String': {
                    const data = mapError(() => bin2str(dataBytes), new BadFormatError("Bad data provided"));
                    return { data, metadata, dataType };
                }
                case 'File': {
                    const fileName = dataType.name;
                    const data = mapError(() => new File([dataBytes], fileName), new BadFormatError("Bad data provided"));
                    return { data, metadata, dataType };
                }
                case 'Binary':
                    return { data: dataBytes, metadata, dataType };
                case 'Json': {
                    const data = mapError(() => JSON.parse(bin2str(dataBytes)), new BadFormatError("Bad data provided"));
                    return { data, metadata, dataType };
                }
            }
        });
    }
    decryptMany(encryptedData) {
        return __awaiter(this, void 0, void 0, function* () {
            const { eSK } = yield this.getKeys();
            const dataIds = encryptedData.map(ed => {
                const dataId = mapError(() => bin2str(ed.slice(0, 36)), new BadFormatError(`Bad data provided`));
                if (dataId.length !== 36)
                    throw new BadFormatError(`Bad data provided`);
                return dataId;
            });
            const resp = yield this.service.getDataKeys(dataIds);
            const encryptedKeys = validateServiceResponse(resp, `Fetching data keys failed for ids ${dataIds}`, keys => dataIds.every(d => keys.find(k => k.documentID === d)));
            const res = Promise.all(encryptedData.map(((ed, i) => __awaiter(this, void 0, void 0, function* () {
                const dataId = dataIds[i];
                const dataKey = yield mapErrorAsync(() => unwrapAESKey(b64str2bin(encryptedKeys.find(ek => ek.documentID === dataId).encryptedSymmetricKey), eSK), new EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`));
                const decrypted = yield mapErrorAsync(() => decryptData(dataKey, ed.slice(36, 48), ed.slice(48)), new EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`));
                let dataBytes, metadata, dataType;
                try {
                    const dataTypeLen = from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))));
                    const dataTypeBytes = decrypted.slice(6, 6 + dataTypeLen);
                    dataType = JSON.parse(bin2str(dataTypeBytes));
                    const metadataLen = from4Bytes(Array.from(new Uint8Array(decrypted.slice(2, 6))));
                    const metadataBytes = decrypted.slice(6 + dataTypeLen, 6 + dataTypeLen + metadataLen);
                    metadata = JSON.parse(bin2str(metadataBytes));
                    dataBytes = decrypted.slice(6 + dataTypeLen + metadataLen);
                }
                catch (_a) {
                    throw new BadFormatError(`Bad data provided for id ${dataId}`);
                }
                switch (dataType.type) {
                    case 'String': {
                        const data = mapError(() => bin2str(dataBytes), new BadFormatError("Bad data provided"));
                        return { data, metadata, dataType };
                    }
                    case 'File': {
                        const fileName = dataType.name;
                        const data = mapError(() => new File([dataBytes], fileName), new BadFormatError("Bad data provided"));
                        return { data, metadata, dataType };
                    }
                    case 'Binary':
                        return { data: dataBytes, metadata, dataType };
                    case 'Json': {
                        const data = mapError(() => JSON.parse(bin2str(dataBytes)), new BadFormatError("Bad data provided"));
                        return { data, metadata, dataType };
                    }
                }
            }))));
            return res;
        });
    }
    changeSecret(newSecret) {
        return __awaiter(this, void 0, void 0, function* () {
            const { eSK, sSK } = yield this.getKeys();
            const new_salt = crypto.getRandomValues(new Uint8Array(16));
            const new_aesKey = yield deriveAESKey(newSecret, new_salt);
            const enc_eSK = yield wrapSecretKey(eSK, new_aesKey, new Uint8Array(12));
            const enc_sSK = yield crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12).map(_ => 1) }, new_aesKey, sSK);
            const updateUserResp = yield this.service.updateUser(enc_eSK, enc_sSK, new_salt);
            validateServiceResponse(updateUserResp, 'Could not upload the new keys');
            yield this.keyStore.storeKey('derived', new_aesKey);
        });
    }
    giveAccessToData(dataIds, userId) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.giveAccess(() => this.service.getDataKeys(dataIds), userId);
        });
    }
    giveAccessToAllData(userId) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.giveAccess(() => this.service.getAllDataKeys(), userId);
        });
    }
    giveAccess(getDataKeys, userId) {
        return __awaiter(this, void 0, void 0, function* () {
            const { eSK } = yield this.getKeys();
            const resp1 = yield this.service.getUsersPublicKey(userId);
            const user = validateServiceResponse(resp1, `Fetching the public key of a user ${userId} failed`);
            const resp2 = yield getDataKeys();
            const encryptedDataKeys = validateServiceResponse(resp2, `Fetching the encrypted data keys failed`);
            const userPK = yield mapErrorAsync(() => importPublicKey(JSON.parse(bin2str(b64str2bin(user.publicEncryptionKey)))), new EncryptionError('Public key in wrong format'));
            const updatedKeys = yield Promise.all(encryptedDataKeys.map((edk) => __awaiter(this, void 0, void 0, function* () {
                const dataKey = yield mapErrorAsync(() => unwrapAESKey(edk.encryptedSymmetricKey, eSK), new EncryptionError(`Could not decrypt a data key for data id ${edk.documentID}`));
                const newDataKey = yield mapErrorAsync(() => wrapAESKey(dataKey, userPK), new EncryptionError(`Could not encrypt data key for user ${userId}`));
                return { documentID: edk.documentID, encryptedSymmetricKey: bin2b64str(newDataKey) };
            })));
            const updateResp = yield this.service.giveAccess(userId, updatedKeys);
            validateServiceResponse(updateResp, `Uploading the encrypted data keys for a user ${userId} failed`);
            return undefined;
        });
    }
}
Blindnet.protocolVersion = "1";
Blindnet.apiUrl = 'https://api.blindnet.io';
Blindnet.testUrl = 'https://test.blindnet.io';
const helper = {
    toBase64: bin2b64str,
    fromBase64: b64str2bin,
    toHex: bin2Hex,
    fromHex: hex2bin
};

exports.Blindnet = Blindnet;
exports.error = error;
exports.util = helper;
