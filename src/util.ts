import { isBrowser } from "./globals"

export function str2bin(str: string): ArrayBuffer {
  return new TextEncoder().encode(str)
}

export function bin2str(ab: ArrayBuffer): string {
  return new TextDecoder().decode(ab)
}

export function b64str2bin(b64str: string): Uint8Array {
  if (isBrowser)
    return Uint8Array.from(window.atob(b64str), c => c.charCodeAt(0))
  else
    return Buffer.from(b64str, 'base64')
}

export function bin2b64str(arrayBuffer: ArrayBuffer): string {
  if (isBrowser) {
    const x = new Uint8Array(arrayBuffer)
    let str = ''
    for (let i = 0; i < x.length; i++) {
      str += String.fromCharCode(x[i])
    }
    return window.btoa(str)
  }
  else
    return Buffer.from(arrayBuffer).toString('base64')
}

export function concat(...buffers: (ArrayBuffer | Uint8Array)[]): ArrayBuffer {
  var res = new Uint8Array(buffers.reduce((acc, cur) => acc + cur.byteLength, 0))
  let offset = 0
  buffers.forEach(buf => {
    res.set((buf instanceof ArrayBuffer) ? new Uint8Array(buf) : buf, offset)
    offset += buf.byteLength
  })
  return res.buffer
}

export function to4Bytes(x: number): Array<number> {
  return [x, (x << 8), (x << 16), (x << 24)].map(z => z >>> 24)
}

export function from4Bytes(bytes: number[] | ArrayBuffer | Uint8Array) {
  return new Uint8Array(bytes).reduce((a, c, i) => a + c * 2 ** (24 - i * 8), 0)
}

export function to2Bytes(x: number): Array<number> {
  return [(x << 16), (x << 24)].map(z => z >>> 24)
}

export function from2Bytes(bytes: number[] | ArrayBuffer | Uint8Array) {
  return new Uint8Array(bytes).reduce((a, c, i) => a + c * 2 ** (8 - i * 8), 0)
}

export function bin2Hex(arr: ArrayBuffer | Uint8Array): string {
  let s = ''
  const h = '0123456789ABCDEF'
  const x = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr
  x.forEach((v) => { s += h[v >> 4] + h[v & 15] })
  return s
}

export function hex2bin(hex: string): Uint8Array {
  for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16))
  return new Uint8Array(bytes)
}

export function mapError<T>(f: () => T, e: Error): T {
  try {
    return f()
  } catch {
    throw e
  }
}

export async function mapErrorAsync<T>(f: () => Promise<T>, e: Error): Promise<T> {
  try {
    return await f()
  } catch {
    throw e
  }
}
