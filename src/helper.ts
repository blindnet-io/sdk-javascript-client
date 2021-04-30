function str2ab(str: string): ArrayBuffer {
  var buf = new ArrayBuffer(str.length * 2);
  var bufView = new Uint16Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function ab2str(ab: ArrayBuffer): string {
  return String.fromCharCode.apply(null, new Uint16Array(ab))
}


function b642arr(b64str: string): Uint8Array {
  return Uint8Array.from(atob(b64str), c => c.charCodeAt(0))
}

function arr2b64(byteArray): string {
  return btoa(Array.from(new Uint8Array(byteArray)).map(val => String.fromCharCode(val)).join(''))
}


function b64url2arr(b64str: string): Uint8Array {
  const unescaped =
    (b64str + '==='.slice((b64str.length + 3) % 4))
      .replace(/-/g, '+')
      .replace(/_/g, '/')

  return Uint8Array.from(atob(unescaped), c => c.charCodeAt(0))
}

function arr2b64url(byteArray): string {
  return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
    return String.fromCharCode(val)
  }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
}


function b64url2str(b64str: string): string {
  const unescaped =
    (b64str + '==='.slice((b64str.length + 3) % 4))
      .replace(/-/g, '+')
      .replace(/_/g, '/')

  return decodeURIComponent(atob(unescaped).split('').map(function (c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
  }).join(''));
}

function decodeJwtPayload(jwt: string) {
  try {
    return JSON.parse(b64url2str(jwt.split('.')[1]))
  } catch {
    throw "JWT in wrong format"
  }
}

// TODO: optimize and unify
function concat(buffer1: ArrayBuffer | Uint8Array, buffer2: ArrayBuffer | Uint8Array): ArrayBuffer {
  var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set((buffer1 instanceof ArrayBuffer) ? new Uint8Array(buffer1) : buffer1, 0);
  tmp.set((buffer2 instanceof ArrayBuffer) ? new Uint8Array(buffer2) : buffer2, buffer1.byteLength);
  return tmp.buffer;
}
function concat3(buffer1: ArrayBuffer | Uint8Array, buffer2: ArrayBuffer | Uint8Array, buffer3: ArrayBuffer | Uint8Array): ArrayBuffer {
  var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength + buffer3.byteLength);
  tmp.set((buffer1 instanceof ArrayBuffer) ? new Uint8Array(buffer1) : buffer1, 0);
  tmp.set((buffer2 instanceof ArrayBuffer) ? new Uint8Array(buffer2) : buffer2, buffer1.byteLength);
  tmp.set((buffer3 instanceof ArrayBuffer) ? new Uint8Array(buffer3) : buffer3, buffer1.byteLength + buffer2.byteLength);
  return tmp.buffer;
}

function getInt64Bytes(x: number) {
  let y = Math.floor(x / 2 ** 32);
  return [y, (y << 8), (y << 16), (y << 24), x, (x << 8), (x << 16), (x << 24)].map(z => z >>> 24)
}

function intFromBytes(byteArr: number[]) {
  return byteArr.reduce((a, c, i) => a + c * 2 ** (56 - i * 8), 0)
}

function rethrow<T>(f: () => T, e: Error): T {
  try {
    return f()
  } catch {
    throw e
  }
}

async function rethrowPromise<T>(f: () => Promise<T>, e: Error): Promise<T> {
  try {
    return await f()
  } catch {
    throw e
  }
}

export {
  str2ab,
  ab2str,
  b642arr,
  arr2b64,
  b64url2arr,
  arr2b64url,
  decodeJwtPayload,
  concat,
  concat3,
  getInt64Bytes,
  intFromBytes,
  rethrow,
  rethrowPromise
}