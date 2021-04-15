export function str2ab(str: string): ArrayBuffer {
  var buf = new ArrayBuffer(str.length * 2);
  var bufView = new Uint16Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function ab2str(ab: ArrayBuffer): string {
  return String.fromCharCode.apply(null, new Uint16Array(ab));
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

export function b64url2arr(b64str: string): Uint8Array {
  const unescaped =
    (b64str + '==='.slice((b64str.length + 3) % 4))
      .replace(/-/g, '+')
      .replace(/_/g, '/')

  return Uint8Array.from(atob(unescaped), c => c.charCodeAt(0))
}

// TODO: optimize
export function arr2b64url(byteArray): string {
  return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
    return String.fromCharCode(val)
  }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
}

export function decodeJwtPayload(jwt: string) {
  try {
    return JSON.parse(b64url2str(jwt.split('.')[1]))
  } catch {
    throw "JWT in wrong format"
  }
}

// TODO: optimize
export function concat(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
  var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp.buffer;
}
