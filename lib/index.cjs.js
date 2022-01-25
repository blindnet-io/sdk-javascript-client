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
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
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

var IndexedDbKeyStore = (function () {
    function IndexedDbKeyStore(storeName) {
        var _this = this;
        if (storeName === void 0) { storeName = 'keys'; }
        this.keys = ['private_enc', 'public_enc', 'private_sign', 'public_sign', 'derived'];
        this.keyLabels = ['eSK', 'ePK', 'sSK', 'sPK', 'aes'];
        this.storeKey = function (type, key) {
            return set(type, key, _this.store);
        };
        this.storeKeys = function (eSK, ePK, sSK, sPK, aes) {
            return setMany([['private_enc', eSK], ['public_enc', ePK], ['private_sign', sSK], ['public_sign', sPK], ['derived', aes]], _this.store);
        };
        this.getKey = function (type) {
            return get(type, _this.store);
        };
        this.getSignKey = function (type) {
            return get(type, _this.store);
        };
        this.getKeys = function () {
            return getMany(_this.keys, _this.store)
                .then(function (res) { return res.reduce(function (acc, cur, i) {
                var _a;
                return (__assign(__assign({}, acc), (_a = {}, _a[_this.keyLabels[i]] = cur, _a)));
            }, {}); });
        };
        this.clear = function () { return clear(_this.store); };
        this.store = createStore('blindnet', storeName);
    }
    return IndexedDbKeyStore;
}());

var isBrowser = typeof window === 'object';

function str2bin(str) {
    return new TextEncoder().encode(str);
}
function bin2str(ab) {
    return new TextDecoder().decode(ab);
}
function b64str2bin(b64str) {
    if (isBrowser)
        return Uint8Array.from(window.atob(b64str), function (c) { return c.charCodeAt(0); });
    else
        return Buffer.from(b64str, 'base64');
}
function bin2b64str(arrayBuffer) {
    if (isBrowser) {
        var x = new Uint8Array(arrayBuffer);
        var str = '';
        for (var i = 0; i < x.length; i++) {
            str += String.fromCharCode(x[i]);
        }
        return window.btoa(str);
    }
    else
        return Buffer.from(arrayBuffer).toString('base64');
}
function concat() {
    var buffers = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        buffers[_i] = arguments[_i];
    }
    var res = new Uint8Array(buffers.reduce(function (acc, cur) { return acc + cur.byteLength; }, 0));
    var offset = 0;
    buffers.forEach(function (buf) {
        res.set((buf instanceof ArrayBuffer) ? new Uint8Array(buf) : buf, offset);
        offset += buf.byteLength;
    });
    return res.buffer;
}
function to4Bytes(x) {
    return [x, (x << 8), (x << 16), (x << 24)].map(function (z) { return z >>> 24; });
}
function from4Bytes(bytes) {
    return new Uint8Array(bytes).reduce(function (a, c, i) { return a + c * Math.pow(2, (24 - i * 8)); }, 0);
}
function to2Bytes(x) {
    return [(x << 16), (x << 24)].map(function (z) { return z >>> 24; });
}
function from2Bytes(bytes) {
    return new Uint8Array(bytes).reduce(function (a, c, i) { return a + c * Math.pow(2, (8 - i * 8)); }, 0);
}
function bin2Hex(arr) {
    var s = '';
    var h = '0123456789ABCDEF';
    var x = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr;
    x.forEach(function (v) { s += h[v >> 4] + h[v & 15]; });
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
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 2, , 3]);
                    return [4, f()];
                case 1: return [2, _b.sent()];
                case 2:
                    _b.sent();
                    throw e;
                case 3: return [2];
            }
        });
    });
}

var util = /*#__PURE__*/Object.freeze({
    __proto__: null,
    str2bin: str2bin,
    bin2str: bin2str,
    b64str2bin: b64str2bin,
    bin2b64str: bin2b64str,
    concat: concat,
    to4Bytes: to4Bytes,
    from4Bytes: from4Bytes,
    to2Bytes: to2Bytes,
    from2Bytes: from2Bytes,
    bin2Hex: bin2Hex,
    hex2bin: hex2bin,
    mapError: mapError,
    mapErrorAsync: mapErrorAsync
});

var BlindnetServiceHttp = (function () {
    function BlindnetServiceHttp(token, apiUrl, protocolVersion) {
        var _this = this;
        this.apiUrl = undefined;
        this.protocolVersion = undefined;
        this.token = undefined;
        this.registerUser = function (ePK, sPK, enc_eSK, enc_sSK, salt, signedToken, signedEncPK) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/users", {
                            method: 'POST',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
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
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (_) { return undefined; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getUserData = function () { return __awaiter(_this, void 0, void 0, function () {
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
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/keys/me", {
                            method: 'GET',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            }
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp, { type: 'UserNotFound' })(mapping)];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getUsersPublicKey = function (userId) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/keys/" + userId, {
                            method: 'GET',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            }
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return (__assign({}, data)); })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getPublicKeys = function (userIds) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/keys", {
                            method: 'POST',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            },
                            body: JSON.stringify({
                                userIds: userIds
                            })
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return data; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getGroupPublicKeys = function (groupId) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/keys", {
                            method: 'POST',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            },
                            body: JSON.stringify({
                                groupId: groupId
                            })
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return data; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.postEncryptedKeys = function (encryptedKeys) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/documents", {
                            method: 'POST',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            },
                            body: JSON.stringify(encryptedKeys)
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return data; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getDataKey = function (dataId) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/documents/keys/" + dataId, {
                            method: 'GET',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            }
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return data; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getAllDataKeys = function () { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/documents/keys", {
                            method: 'GET',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            }
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return data; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.getDataKeys = function (dataIds) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/documents/keys", {
                            method: 'POST',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            },
                            body: JSON.stringify({
                                data_ids: dataIds
                            })
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (data) { return data; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.updateUser = function (esk, ssk, salt) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/keys/me", {
                            method: 'PUT',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            },
                            body: JSON.stringify({
                                encryptedPrivateEncryptionKey: bin2b64str(esk),
                                encryptedPrivateSigningKey: bin2b64str(ssk),
                                keyDerivationSalt: bin2b64str(salt)
                            })
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (_) { return undefined; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.giveAccess = function (userId, docKeys) { return __awaiter(_this, void 0, void 0, function () {
            var serverResp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, fetch(this.apiUrl + "/api/v" + this.protocolVersion + "/documents/keys/user/" + userId, {
                            method: 'PUT',
                            mode: 'cors',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': "Bearer " + this.token
                            },
                            body: JSON.stringify(docKeys)
                        })];
                    case 1:
                        serverResp = _a.sent();
                        return [4, handleResponse(serverResp)(function (_) { return undefined; })];
                    case 2: return [2, _a.sent()];
                }
            });
        }); };
        this.updateToken = function (token) { return _this.token = token; };
        this.clearToken = function () { return _this.token = undefined; };
        this.token = token;
        this.apiUrl = apiUrl;
        this.protocolVersion = protocolVersion;
    }
    return BlindnetServiceHttp;
}());
var handleResponse = function (resp, notFoundData) { return function (f) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, body;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _a = resp.status;
                switch (_a) {
                    case 200: return [3, 1];
                    case 401: return [3, 3];
                    case 400: return [3, 4];
                }
                return [3, 5];
            case 1: return [4, resp.json()];
            case 2:
                body = _b.sent();
                return [2, { type: 'Success', data: f(body) }];
            case 3: return [2, { type: 'AuthenticationNeeded' }];
            case 4:
                {
                    if (notFoundData != undefined)
                        return [2, { type: 'Success', data: notFoundData }];
                    else
                        return [2, { type: 'Failed' }];
                }
            case 5: return [2, { type: 'Failed' }];
        }
    });
}); }; };

var AuthenticationError = (function (_super) {
    __extends(AuthenticationError, _super);
    function AuthenticationError() {
        var _newTarget = this.constructor;
        var _this = _super.call(this, 'Authentication to blindnet failed. Please generate a valid token.') || this;
        _this.code = 'blindnet.authentication';
        _this.name = 'AuthenticationError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return AuthenticationError;
}(Error));
var UserNotInitializedError = (function (_super) {
    __extends(UserNotInitializedError, _super);
    function UserNotInitializedError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 'blindnet.user_not_initialized';
        _this.name = 'UserNotInitializedError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return UserNotInitializedError;
}(Error));
var SecretError = (function (_super) {
    __extends(SecretError, _super);
    function SecretError() {
        var _newTarget = this.constructor;
        var _this = _super.call(this, 'Wrong secret provided.') || this;
        _this.code = 'blindnet.secret';
        _this.name = 'SecretError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return SecretError;
}(Error));
var BadFormatError = (function (_super) {
    __extends(BadFormatError, _super);
    function BadFormatError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 'blindnet.data_format';
        _this.name = 'BadFormatError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return BadFormatError;
}(Error));
var EncryptionError = (function (_super) {
    __extends(EncryptionError, _super);
    function EncryptionError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 'blindnet.encryption';
        _this.name = 'EncryptionError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return EncryptionError;
}(Error));
var BlindnetServiceError = (function (_super) {
    __extends(BlindnetServiceError, _super);
    function BlindnetServiceError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 'blindnet.service';
        _this.name = 'BlindnetServiceError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return BlindnetServiceError;
}(Error));
var NotEncryptabeError = (function (_super) {
    __extends(NotEncryptabeError, _super);
    function NotEncryptabeError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 'blindnet.not_encryptable';
        _this.name = 'NotEncryptabeError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return NotEncryptabeError;
}(Error));
var NoAccessError = (function (_super) {
    __extends(NoAccessError, _super);
    function NoAccessError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 7;
        _this.name = 'NoAccessError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return NoAccessError;
}(Error));
var UserNotFoundError = (function (_super) {
    __extends(UserNotFoundError, _super);
    function UserNotFoundError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        _this.code = 8;
        _this.name = 'UserNotFoundError';
        Object.setPrototypeOf(_this, _newTarget.prototype);
        return _this;
    }
    return UserNotFoundError;
}(Error));

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

function deriveAESKey(password, salt, extractable) {
    if (extractable === void 0) { extractable = false; }
    return __awaiter(this, void 0, void 0, function () {
        var s, passKey, aesKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    s = typeof salt === 'string' ? b64str2bin(salt) : salt;
                    return [4, crypto.subtle.importKey("raw", str2bin(password), "PBKDF2", false, ["deriveKey"])];
                case 1:
                    passKey = _a.sent();
                    return [4, crypto.subtle.deriveKey({
                            name: "PBKDF2",
                            salt: s,
                            iterations: 100000,
                            hash: "SHA-256",
                        }, passKey, { name: "AES-GCM", length: 256 }, extractable, ["decrypt", "encrypt", "wrapKey", "unwrapKey"])];
                case 2:
                    aesKey = _a.sent();
                    return [2, aesKey];
            }
        });
    });
}
function deriveSecrets(seed) {
    return __awaiter(this, void 0, void 0, function () {
        var s, passKey, salt, derivedBits;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    s = (seed.length === 0 || seed == undefined) ? 'seed' : seed;
                    return [4, crypto.subtle.importKey("raw", str2bin(s), "PBKDF2", false, ["deriveBits"])];
                case 1:
                    passKey = _a.sent();
                    salt = new Uint8Array([241, 211, 153, 239, 17, 34, 5, 112, 167, 218, 57, 131, 99, 29, 243, 84]);
                    return [4, crypto.subtle.deriveBits({
                            "name": "PBKDF2",
                            salt: salt,
                            "iterations": 64206,
                            "hash": "SHA-256"
                        }, passKey, 512)];
                case 2:
                    derivedBits = _a.sent();
                    return [2, { secret1: new Uint8Array(derivedBits, 0, 32), secret2: new Uint8Array(derivedBits, 32, 32) }];
            }
        });
    });
}
function generateRandomAESKey() {
    return __awaiter(this, void 0, void 0, function () {
        var key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4, crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])];
                case 1:
                    key = _a.sent();
                    return [2, key];
            }
        });
    });
}
function generateRandomRSAKeyPair() {
    return __awaiter(this, void 0, void 0, function () {
        var keyPair;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4, crypto.subtle.generateKey({
                        name: "RSA-OAEP",
                        modulusLength: 4096,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256"
                    }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"])];
                case 1:
                    keyPair = _a.sent();
                    return [2, keyPair];
            }
        });
    });
}
function generateRandomSigningKeyPair() {
    return __awaiter(this, void 0, void 0, function () {
        var privateKey, publicKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    privateKey = nobleEd25519_1.randomPrivateKey();
                    return [4, nobleEd25519_4(privateKey)];
                case 1:
                    publicKey = _a.sent();
                    return [2, { privateKey: privateKey, publicKey: publicKey }];
            }
        });
    });
}
function sign(toSign, secretKey) {
    return __awaiter(this, void 0, void 0, function () {
        var ts;
        return __generator(this, function (_a) {
            ts = typeof toSign === 'string' ? str2bin(toSign) : toSign;
            return [2, nobleEd25519_3(new Uint8Array(ts), secretKey)];
        });
    });
}
function importPublicKey(publicKey) {
    return crypto.subtle.importKey("jwk", publicKey, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["wrapKey", "encrypt"]);
}
function exportPublicKey(publicKey) {
    return crypto.subtle.exportKey("jwk", publicKey);
}
function wrapSecretKey(secretKey, aesKey, iv) {
    return __awaiter(this, void 0, void 0, function () {
        var wrappedSk;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4, crypto.subtle.wrapKey("jwk", secretKey, aesKey, { name: "AES-GCM", iv: iv })];
                case 1:
                    wrappedSk = _a.sent();
                    return [2, wrappedSk];
            }
        });
    });
}
function unwrapSecretKey(wrappedSk, aesKey, iv) {
    return __awaiter(this, void 0, void 0, function () {
        var wsk;
        return __generator(this, function (_a) {
            wsk = typeof wrappedSk === 'string' ? b64str2bin(wrappedSk) : wrappedSk;
            return [2, crypto.subtle.unwrapKey("jwk", wsk, aesKey, { name: "AES-GCM", iv: iv }, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt", "unwrapKey"])];
        });
    });
}
function wrapAESKey(aesKey, wrappingKey) {
    return crypto.subtle.wrapKey("jwk", aesKey, wrappingKey, { name: "RSA-OAEP" });
}
function unwrapAESKey(wrappedKey, secretKey) {
    return __awaiter(this, void 0, void 0, function () {
        var wk, key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    wk = typeof wrappedKey === 'string' ? b64str2bin(wrappedKey) : wrappedKey;
                    return [4, crypto.subtle.unwrapKey("jwk", wk, secretKey, { name: "RSA-OAEP" }, { name: "AES-GCM", length: 256 }, true, ['encrypt', 'decrypt'])];
                case 1:
                    key = _a.sent();
                    return [2, key];
            }
        });
    });
}
function encryptData(aesKey, iv, data) {
    return __awaiter(this, void 0, void 0, function () {
        var encrypted;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4, crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, data)];
                case 1:
                    encrypted = _a.sent();
                    return [2, encrypted];
            }
        });
    });
}
function decryptData(aesKey, iv, encrypted) {
    return __awaiter(this, void 0, void 0, function () {
        var decrypted;
        return __generator(this, function (_a) {
            decrypted = crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encrypted);
            return [2, decrypted];
        });
    });
}

function validateServiceResponse(resp, errorMsg, isValid) {
    if (isValid === void 0) { isValid = function (_) { return true; }; }
    if (resp.type === 'AuthenticationNeeded')
        throw new AuthenticationError();
    else if (resp.type === 'Failed')
        throw new BlindnetServiceError(errorMsg);
    else if (!isValid(resp.data))
        throw new BlindnetServiceError("Data returned from server not valid");
    else
        return resp.data;
}
var CaptureBuilder = (function () {
    function CaptureBuilder(data, service) {
        this.data = data;
        this.service = service;
    }
    CaptureBuilder.prototype.withMetadata = function (metadata) {
        this.metadata = metadata;
        return this;
    };
    CaptureBuilder.prototype.forUser = function (userId) {
        this.userIds = [userId];
        return this;
    };
    CaptureBuilder.prototype.forUsers = function (userIds) {
        this.userIds = userIds;
        return this;
    };
    CaptureBuilder.prototype.forGroup = function (groupId) {
        this.groupId = groupId;
        return this;
    };
    CaptureBuilder.prototype.encrypt = function () {
        return __awaiter(this, void 0, void 0, function () {
            var data, metadata, dataBin, dataType, dataTypeBin, dataTypeLenBytes, metadataBin, metadataLenBytes, resp, users, toEncrypt, dataKey, iv, encrypted, encryptedUserKeys, postKeysResp, dataId, encryptedData;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        try {
                            data = this.data;
                            if (this.metadata == undefined)
                                metadata = {};
                            else
                                metadata = this.metadata;
                        }
                        catch (_b) {
                            throw new BadFormatError('Data in bad format. Expected an object { data, metadata }');
                        }
                        if (data === null || data === undefined)
                            throw new BadFormatError('Data can\'t be undefined or null');
                        if (typeof metadata !== 'object')
                            throw new BadFormatError('Metadata has to be an object');
                        if (!(typeof data === 'string')) return [3, 1];
                        dataBin = str2bin(data);
                        dataType = { type: 'String' };
                        return [3, 4];
                    case 1:
                        if (!(data instanceof File)) return [3, 3];
                        return [4, data.arrayBuffer()];
                    case 2:
                        dataBin = _a.sent();
                        dataType = { type: 'File', name: data.name };
                        return [3, 4];
                    case 3:
                        if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
                            dataBin = data;
                            dataType = { type: 'Binary' };
                        }
                        else if (typeof data === 'object') {
                            dataBin = mapError(function () { return str2bin(JSON.stringify(data)); }, new BadFormatError('Data in bad format'));
                            dataType = { type: 'Json' };
                        }
                        else
                            throw new BadFormatError('Encryption of provided data format is not supported');
                        _a.label = 4;
                    case 4:
                        dataTypeBin = str2bin(JSON.stringify(dataType));
                        dataTypeLenBytes = to2Bytes(dataTypeBin.byteLength);
                        metadataBin = str2bin(JSON.stringify(metadata));
                        metadataLenBytes = to4Bytes(metadataBin.byteLength);
                        if (!(this.userIds != null && Object.prototype.toString.call(this.userIds) === '[object Array]')) return [3, 6];
                        return [4, this.service.getPublicKeys(this.userIds)];
                    case 5:
                        resp = _a.sent();
                        return [3, 9];
                    case 6:
                        if (!(this.groupId != null && typeof this.groupId === 'string')) return [3, 8];
                        return [4, this.service.getGroupPublicKeys(this.groupId)];
                    case 7:
                        resp = _a.sent();
                        return [3, 9];
                    case 8: throw new NotEncryptabeError('You must specify a list of users or a group to encrypt the data for');
                    case 9:
                        users = validateServiceResponse(resp, 'Fetching public keys failed');
                        if (users.length == 0)
                            throw new NotEncryptabeError('Selected users not found');
                        toEncrypt = concat(new Uint8Array(dataTypeLenBytes), new Uint8Array(metadataLenBytes), dataTypeBin, metadataBin, dataBin);
                        return [4, mapErrorAsync(function () { return generateRandomAESKey(); }, new EncryptionError("Could not generate key"))];
                    case 10:
                        dataKey = _a.sent();
                        iv = crypto.getRandomValues(new Uint8Array(12));
                        return [4, mapErrorAsync(function () { return encryptData(dataKey, iv, toEncrypt); }, new EncryptionError("Could not encrypt data"))];
                    case 11:
                        encrypted = _a.sent();
                        return [4, Promise.all(users.map(function (user) { return __awaiter(_this, void 0, void 0, function () {
                                var PK, encryptedDataKey;
                                return __generator(this, function (_a) {
                                    switch (_a.label) {
                                        case 0: return [4, mapErrorAsync(function () { return importPublicKey(JSON.parse(bin2str(b64str2bin(user.publicEncryptionKey)))); }, new EncryptionError("Public key in wrong format"))];
                                        case 1:
                                            PK = _a.sent();
                                            return [4, mapErrorAsync(function () { return wrapAESKey(dataKey, PK); }, new EncryptionError("Could not encrypt data key"))];
                                        case 2:
                                            encryptedDataKey = _a.sent();
                                            return [2, { userID: user.userID, encryptedSymmetricKey: bin2b64str(encryptedDataKey) }];
                                    }
                                });
                            }); }))];
                    case 12:
                        encryptedUserKeys = _a.sent();
                        return [4, this.service.postEncryptedKeys(encryptedUserKeys)];
                    case 13:
                        postKeysResp = _a.sent();
                        dataId = validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys');
                        encryptedData = concat(str2bin(dataId), iv.buffer, encrypted);
                        return [2, { dataId: dataId, encryptedData: encryptedData }];
                }
            });
        });
    };
    return CaptureBuilder;
}());
var Blindnet = (function () {
    function Blindnet(service, keyStore) {
        this.service = service;
        this.keyStore = keyStore;
    }
    Blindnet.testBrowser = function () {
        return __awaiter(this, void 0, void 0, function () {
            var aesKey, rsaKeyPair, eccKeyPair, keyStore, key, keys, e_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 8, , 9]);
                        aesKey = generateRandomAESKey();
                        if (!(aesKey instanceof Promise))
                            return [2, false];
                        return [4, generateRandomRSAKeyPair()];
                    case 1:
                        rsaKeyPair = _a.sent();
                        return [4, generateRandomSigningKeyPair()];
                    case 2:
                        eccKeyPair = _a.sent();
                        keyStore = new IndexedDbKeyStore();
                        return [4, keyStore.storeKey('test_key', aesKey)];
                    case 3:
                        _a.sent();
                        return [4, keyStore.storeKeys(rsaKeyPair.privateKey, rsaKeyPair.publicKey, eccKeyPair.privateKey, eccKeyPair.publicKey, aesKey)];
                    case 4:
                        _a.sent();
                        return [4, keyStore.getKey('test_key')];
                    case 5:
                        key = _a.sent();
                        if (!(key instanceof CryptoKey))
                            return [2, false];
                        return [4, keyStore.getKeys()];
                    case 6:
                        keys = _a.sent();
                        if (!(keys.eSK instanceof CryptoKey) ||
                            !(keys.ePK instanceof CryptoKey) ||
                            !(keys.sSK instanceof Uint8Array) ||
                            !(keys.sPK instanceof Uint8Array) ||
                            !(keys.aes instanceof CryptoKey))
                            return [2, false];
                        return [4, keyStore.clear()];
                    case 7:
                        _a.sent();
                        return [3, 9];
                    case 8:
                        e_1 = _a.sent();
                        console.log(e_1);
                        return [2, false];
                    case 9: return [2, true];
                }
            });
        });
    };
    Blindnet.initCustomKeyStore = function (token, keyStore, apiUrl) {
        if (apiUrl === void 0) { apiUrl = Blindnet.apiUrl; }
        var service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion);
        return new Blindnet(service, keyStore);
    };
    Blindnet.init = function (token, apiUrl) {
        if (apiUrl === void 0) { apiUrl = Blindnet.apiUrl; }
        var service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion);
        var keyStore = new IndexedDbKeyStore();
        return new Blindnet(service, keyStore);
    };
    Blindnet.disconnect = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, (new IndexedDbKeyStore()).clear()];
                    case 1:
                        _a.sent();
                        return [2];
                }
            });
        });
    };
    Blindnet.prototype.disconnect = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this.service.clearToken();
                        return [4, this.keyStore.clear()];
                    case 1:
                        _a.sent();
                        return [2];
                }
            });
        });
    };
    Blindnet.prototype.refreshToken = function (token) {
        this.service.updateToken(token);
    };
    Blindnet.deriveSecrets = function (seed) {
        return __awaiter(this, void 0, void 0, function () {
            var _a, secret1, secret2, blindnetSecret, appSecret;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4, deriveSecrets(seed)];
                    case 1:
                        _a = _b.sent(), secret1 = _a.secret1, secret2 = _a.secret2;
                        blindnetSecret = bin2b64str(secret1);
                        appSecret = bin2b64str(secret2);
                        return [2, { blindnetSecret: blindnetSecret, appSecret: appSecret }];
                }
            });
        });
    };
    Blindnet.prototype.getKeys = function () {
        return __awaiter(this, void 0, void 0, function () {
            var keys;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, mapErrorAsync(function () { return _this.keyStore.getKeys(); }, new UserNotInitializedError('Keys not initialized'))];
                    case 1:
                        keys = _a.sent();
                        if (Object.values(keys).length === 0 || Object.values(keys).some(function (x) { return x == undefined; }))
                            throw new UserNotInitializedError('Keys not initialized');
                        return [2, keys];
                }
            });
        });
    };
    Blindnet.prototype.connect = function (secret) {
        return __awaiter(this, void 0, void 0, function () {
            var resp, getUserResp, _a, _b, eSK, ePK, _c, sSK, sPK, encPKexp, _d, _e, _f, _g, signedToken, signedEncPK, salt, aesKey, enc_eSK, enc_sSK, resp_1, _h, enc_PK, e_enc_SK_1, sign_PK, e_sign_SK_1, salt, ePK, aesKey_1, eSK, sSK;
            return __generator(this, function (_j) {
                switch (_j.label) {
                    case 0: return [4, this.keyStore.clear()];
                    case 1:
                        _j.sent();
                        return [4, this.service.getUserData()];
                    case 2:
                        resp = _j.sent();
                        getUserResp = validateServiceResponse(resp, 'Fetching user data failed');
                        _a = getUserResp.type;
                        switch (_a) {
                            case 'UserNotFound': return [3, 3];
                            case 'UserFound': return [3, 14];
                        }
                        return [3, 20];
                    case 3: return [4, generateRandomRSAKeyPair()];
                    case 4:
                        _b = _j.sent(), eSK = _b.privateKey, ePK = _b.publicKey;
                        return [4, generateRandomSigningKeyPair()];
                    case 5:
                        _c = _j.sent(), sSK = _c.privateKey, sPK = _c.publicKey;
                        _e = (_d = util).str2bin;
                        _g = (_f = JSON).stringify;
                        return [4, exportPublicKey(ePK)];
                    case 6:
                        encPKexp = _e.apply(_d, [_g.apply(_f, [_j.sent()])]);
                        return [4, sign(this.service.token, sSK)];
                    case 7:
                        signedToken = _j.sent();
                        return [4, sign(encPKexp, sSK)];
                    case 8:
                        signedEncPK = _j.sent();
                        salt = crypto.getRandomValues(new Uint8Array(16));
                        return [4, deriveAESKey(secret, salt)];
                    case 9:
                        aesKey = _j.sent();
                        return [4, wrapSecretKey(eSK, aesKey, new Uint8Array(12))];
                    case 10:
                        enc_eSK = _j.sent();
                        return [4, encryptData(aesKey, new Uint8Array(12).map(function (_) { return 1; }), concat(sSK, sPK))];
                    case 11:
                        enc_sSK = _j.sent();
                        return [4, this.service.registerUser(encPKexp, sPK, enc_eSK, enc_sSK, salt, signedToken, signedEncPK)];
                    case 12:
                        resp_1 = _j.sent();
                        validateServiceResponse(resp_1, 'User could not be registered');
                        return [4, this.keyStore.storeKeys(eSK, ePK, sSK, sPK, aesKey)];
                    case 13:
                        _j.sent();
                        return [2, undefined];
                    case 14:
                        _h = getUserResp.userData, enc_PK = _h.enc_PK, e_enc_SK_1 = _h.e_enc_SK, sign_PK = _h.sign_PK, e_sign_SK_1 = _h.e_sign_SK, salt = _h.salt;
                        return [4, importPublicKey(JSON.parse(bin2str(b64str2bin(enc_PK))))];
                    case 15:
                        ePK = _j.sent();
                        return [4, deriveAESKey(secret, salt)];
                    case 16:
                        aesKey_1 = _j.sent();
                        return [4, mapErrorAsync(function () { return unwrapSecretKey(e_enc_SK_1, aesKey_1, new Uint8Array(12)); }, new SecretError())];
                    case 17:
                        eSK = _j.sent();
                        return [4, mapErrorAsync(function () { return decryptData(aesKey_1, new Uint8Array(12).map(function (_) { return 1; }), b64str2bin(e_sign_SK_1)); }, new SecretError())];
                    case 18:
                        sSK = _j.sent();
                        return [4, this.keyStore.storeKeys(eSK, ePK, new Uint8Array(sSK).slice(0, 32), b64str2bin(sign_PK), aesKey_1)];
                    case 19:
                        _j.sent();
                        return [2, undefined];
                    case 20: return [2];
                }
            });
        });
    };
    Blindnet.prototype.capture = function (data) {
        return new CaptureBuilder(data, this.service);
    };
    Blindnet.prototype.decrypt = function (encryptedData) {
        return __awaiter(this, void 0, void 0, function () {
            var eSK, dataId, resp, encryptedDataKey, dataKey, decrypted, dataBytes, metadata, dataType, dataTypeLen, dataTypeBytes, metadataLen, metadataBytes, data, fileName_1, data, data;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, this.getKeys()];
                    case 1:
                        eSK = (_a.sent()).eSK;
                        dataId = mapError(function () { return bin2str(encryptedData.slice(0, 36)); }, new BadFormatError("Bad data provided"));
                        if (dataId.length !== 36)
                            throw new BadFormatError("Bad data provided");
                        return [4, this.service.getDataKey(dataId)];
                    case 2:
                        resp = _a.sent();
                        encryptedDataKey = validateServiceResponse(resp, "Fetching data key failed for data with id " + dataId);
                        return [4, mapErrorAsync(function () { return unwrapAESKey(b64str2bin(encryptedDataKey), eSK); }, new EncryptionError("Encrypted data key for data with id " + dataId + " could not be decrypted"))];
                    case 3:
                        dataKey = _a.sent();
                        return [4, mapErrorAsync(function () { return decryptData(dataKey, encryptedData.slice(36, 48), encryptedData.slice(48)); }, new EncryptionError("Encrypted data with id " + dataId + " could not be decrypted"))];
                    case 4:
                        decrypted = _a.sent();
                        try {
                            dataTypeLen = from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))));
                            dataTypeBytes = decrypted.slice(6, 6 + dataTypeLen);
                            dataType = JSON.parse(bin2str(dataTypeBytes));
                            metadataLen = from4Bytes(Array.from(new Uint8Array(decrypted.slice(2, 6))));
                            metadataBytes = decrypted.slice(6 + dataTypeLen, 6 + dataTypeLen + metadataLen);
                            metadata = JSON.parse(bin2str(metadataBytes));
                            dataBytes = decrypted.slice(6 + dataTypeLen + metadataLen);
                        }
                        catch (_b) {
                            throw new BadFormatError("Bad data provided");
                        }
                        switch (dataType.type) {
                            case 'String': {
                                data = mapError(function () { return bin2str(dataBytes); }, new BadFormatError("Bad data provided"));
                                return [2, { data: data, metadata: metadata, dataType: dataType }];
                            }
                            case 'File': {
                                fileName_1 = dataType.name;
                                data = mapError(function () { return new File([dataBytes], fileName_1); }, new BadFormatError("Bad data provided"));
                                return [2, { data: data, metadata: metadata, dataType: dataType }];
                            }
                            case 'Binary':
                                return [2, { data: dataBytes, metadata: metadata, dataType: dataType }];
                            case 'Json': {
                                data = mapError(function () { return JSON.parse(bin2str(dataBytes)); }, new BadFormatError("Bad data provided"));
                                return [2, { data: data, metadata: metadata, dataType: dataType }];
                            }
                        }
                        return [2];
                }
            });
        });
    };
    Blindnet.prototype.decryptMany = function (encryptedData) {
        return __awaiter(this, void 0, void 0, function () {
            var eSK, dataIds, resp, encryptedKeys, res;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, this.getKeys()];
                    case 1:
                        eSK = (_a.sent()).eSK;
                        dataIds = encryptedData.map(function (ed) {
                            var dataId = mapError(function () { return bin2str(ed.slice(0, 36)); }, new BadFormatError("Bad data provided"));
                            if (dataId.length !== 36)
                                throw new BadFormatError("Bad data provided");
                            return dataId;
                        });
                        return [4, this.service.getDataKeys(dataIds)];
                    case 2:
                        resp = _a.sent();
                        encryptedKeys = validateServiceResponse(resp, "Fetching data keys failed for ids " + dataIds, function (keys) { return dataIds.every(function (d) { return keys.find(function (k) { return k.documentID === d; }); }); });
                        res = Promise.all(encryptedData.map((function (ed, i) { return __awaiter(_this, void 0, void 0, function () {
                            var dataId, dataKey, decrypted, dataBytes, metadata, dataType, dataTypeLen, dataTypeBytes, metadataLen, metadataBytes, data, fileName_2, data, data;
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        dataId = dataIds[i];
                                        return [4, mapErrorAsync(function () { return unwrapAESKey(b64str2bin(encryptedKeys.find(function (ek) { return ek.documentID === dataId; }).encryptedSymmetricKey), eSK); }, new EncryptionError("Encrypted data key for data with id " + dataId + " could not be decrypted"))];
                                    case 1:
                                        dataKey = _a.sent();
                                        return [4, mapErrorAsync(function () { return decryptData(dataKey, ed.slice(36, 48), ed.slice(48)); }, new EncryptionError("Encrypted data with id " + dataId + " could not be decrypted"))];
                                    case 2:
                                        decrypted = _a.sent();
                                        try {
                                            dataTypeLen = from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))));
                                            dataTypeBytes = decrypted.slice(6, 6 + dataTypeLen);
                                            dataType = JSON.parse(bin2str(dataTypeBytes));
                                            metadataLen = from4Bytes(Array.from(new Uint8Array(decrypted.slice(2, 6))));
                                            metadataBytes = decrypted.slice(6 + dataTypeLen, 6 + dataTypeLen + metadataLen);
                                            metadata = JSON.parse(bin2str(metadataBytes));
                                            dataBytes = decrypted.slice(6 + dataTypeLen + metadataLen);
                                        }
                                        catch (_b) {
                                            throw new BadFormatError("Bad data provided for id " + dataId);
                                        }
                                        switch (dataType.type) {
                                            case 'String': {
                                                data = mapError(function () { return bin2str(dataBytes); }, new BadFormatError("Bad data provided"));
                                                return [2, { data: data, metadata: metadata, dataType: dataType }];
                                            }
                                            case 'File': {
                                                fileName_2 = dataType.name;
                                                data = mapError(function () { return new File([dataBytes], fileName_2); }, new BadFormatError("Bad data provided"));
                                                return [2, { data: data, metadata: metadata, dataType: dataType }];
                                            }
                                            case 'Binary':
                                                return [2, { data: dataBytes, metadata: metadata, dataType: dataType }];
                                            case 'Json': {
                                                data = mapError(function () { return JSON.parse(bin2str(dataBytes)); }, new BadFormatError("Bad data provided"));
                                                return [2, { data: data, metadata: metadata, dataType: dataType }];
                                            }
                                        }
                                        return [2];
                                }
                            });
                        }); })));
                        return [2, res];
                }
            });
        });
    };
    Blindnet.prototype.changeSecret = function (newSecret, oldSecret) {
        return __awaiter(this, void 0, void 0, function () {
            var _a, eSK, sSK, new_salt, new_aesKey, enc_eSK, enc_sSK, updateUserResp;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4, this.getKeys()];
                    case 1:
                        _a = _b.sent(), eSK = _a.eSK, sSK = _a.sSK;
                        new_salt = crypto.getRandomValues(new Uint8Array(16));
                        return [4, deriveAESKey(newSecret, new_salt)];
                    case 2:
                        new_aesKey = _b.sent();
                        return [4, wrapSecretKey(eSK, new_aesKey, new Uint8Array(12))];
                    case 3:
                        enc_eSK = _b.sent();
                        return [4, crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12).map(function (_) { return 1; }) }, new_aesKey, sSK)];
                    case 4:
                        enc_sSK = _b.sent();
                        return [4, this.service.updateUser(enc_eSK, enc_sSK, new_salt)];
                    case 5:
                        updateUserResp = _b.sent();
                        validateServiceResponse(updateUserResp, 'Could not upload the new keys');
                        return [4, this.keyStore.storeKey('derived', new_aesKey)];
                    case 6:
                        _b.sent();
                        return [2];
                }
            });
        });
    };
    Blindnet.prototype.giveAccess = function (userId) {
        return __awaiter(this, void 0, void 0, function () {
            var eSK, resp1, user, resp2, encryptedDataKeys, userPK, updatedKeys, updateResp;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4, this.getKeys()];
                    case 1:
                        eSK = (_a.sent()).eSK;
                        return [4, this.service.getUsersPublicKey(userId)];
                    case 2:
                        resp1 = _a.sent();
                        user = validateServiceResponse(resp1, "Fetching the public key of a user " + userId + " failed");
                        return [4, this.service.getAllDataKeys()];
                    case 3:
                        resp2 = _a.sent();
                        encryptedDataKeys = validateServiceResponse(resp2, "Fetching the encrypted data keys failed");
                        return [4, mapErrorAsync(function () { return importPublicKey(JSON.parse(bin2str(b64str2bin(user.publicEncryptionKey)))); }, new EncryptionError('Public key in wrong format'))];
                    case 4:
                        userPK = _a.sent();
                        return [4, Promise.all(encryptedDataKeys.map(function (edk) { return __awaiter(_this, void 0, void 0, function () {
                                var dataKey, newDataKey;
                                return __generator(this, function (_a) {
                                    switch (_a.label) {
                                        case 0: return [4, mapErrorAsync(function () { return unwrapAESKey(edk.encryptedSymmetricKey, eSK); }, new EncryptionError("Could not decrypt a data key for data id " + edk.documentID))];
                                        case 1:
                                            dataKey = _a.sent();
                                            return [4, mapErrorAsync(function () { return wrapAESKey(dataKey, userPK); }, new EncryptionError("Could not encrypt data key for user " + userId))];
                                        case 2:
                                            newDataKey = _a.sent();
                                            return [2, { documentID: edk.documentID, encryptedSymmetricKey: bin2b64str(newDataKey) }];
                                    }
                                });
                            }); }))];
                    case 5:
                        updatedKeys = _a.sent();
                        return [4, this.service.giveAccess(userId, updatedKeys)];
                    case 6:
                        updateResp = _a.sent();
                        validateServiceResponse(updateResp, "Uploading the encrypted data keys for a user " + userId + " failed");
                        return [2, undefined];
                }
            });
        });
    };
    Blindnet.protocolVersion = "1";
    Blindnet.apiUrl = 'https://api.blindnet.io';
    Blindnet.testUrl = 'https://test.blindnet.io';
    return Blindnet;
}());
var helper = {
    toBase64: bin2b64str,
    fromBase64: b64str2bin,
    toHex: bin2Hex,
    fromHex: hex2bin
};

exports.Blindnet = Blindnet;
exports.error = error;
exports.util = helper;
