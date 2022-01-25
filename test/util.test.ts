import * as chai from 'chai'
import * as util from '../src/util'

chai.use(require('chai-as-promised'))

const { expect } = chai

describe('str2bin', () => {
  it('should convert a string to array buffer', () => {
    const s = 'convert me'
    const res = util.str2bin(s)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([99, 111, 110, 118, 101, 114, 116, 32, 109, 101]))
  })
})

describe('bin2str', () => {
  it('should convert an array buffer to string', () => {
    const buf = new Uint8Array([99, 111, 110, 118, 101, 114, 116, 32, 109, 101]).buffer
    const res = util.bin2str(buf)

    expect(res).to.equal('convert me')
  })
})

describe('b64str2bin', () => {
  it('should convert a base 64 string to byte array', () => {
    const b64str = 't9wS6Bif9MefxtaEer1GTg=='
    const res = util.b64str2bin(b64str)

    expect(res).to.eql(new Uint8Array([183, 220, 18, 232, 24, 159, 244, 199, 159, 198, 214, 132, 122, 189, 70, 78]))
  })
})

describe('bin2b64str', () => {
  it('should convert a byte array to base 64 string', () => {
    const arr = new Uint8Array([183, 220, 18, 232, 24, 159, 244, 199, 159, 198, 214, 132, 122, 189, 70, 78])
    const res = util.bin2b64str(arr)

    expect(res).to.equal('t9wS6Bif9MefxtaEer1GTg==')
  })
})

describe('concat', () => {
  it('should concatenate two Uint8Array objects', () => {
    const arr1 = new Uint8Array([1, 2, 3, 4])
    const arr2 = new Uint8Array([5, 6, 7, 8])
    const res = util.concat(arr1, arr2)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
  })
  it('should concatenate two ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3, 4]).buffer
    const arr2 = new Uint8Array([5, 6, 7, 8]).buffer
    const res = util.concat(arr1, arr2)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
  })
  it('should concatenate Uint8Array and ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3, 4])
    const arr2 = new Uint8Array([5, 6, 7, 8]).buffer
    const res = util.concat(arr1, arr2)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
  })
  it('should concatenate three Uint8Array objects', () => {
    const arr1 = new Uint8Array([1, 2, 3])
    const arr2 = new Uint8Array([4, 5, 6])
    const arr3 = new Uint8Array([7, 8, 9])
    const res = util.concat(arr1, arr2, arr3)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
  })
  it('should concatenate three ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3]).buffer
    const arr2 = new Uint8Array([4, 5, 6]).buffer
    const arr3 = new Uint8Array([7, 8, 9]).buffer
    const res = util.concat(arr1, arr2, arr3)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
  })
  it('should concatenate mix of Uint8Array and ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3]).buffer
    const arr2 = new Uint8Array([4, 5, 6])
    const arr3 = new Uint8Array([7, 8, 9]).buffer
    const res = util.concat(arr1, arr2, arr3)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
  })
})

describe('num2Bytes', () => {
  it('should convert a number to 4 byte array', () => {
    const n = 123456789
    const res = util.to4Bytes(n)

    expect(res).to.eql([7, 91, 205, 21])
  })
})

describe('from4Bytes', () => {
  it('should convert a 4 byte array to number', () => {
    const arr = [7, 91, 205, 21]
    const res = util.from4Bytes(arr)

    expect(res).to.eql(123456789)
  })
})

describe('to2Bytes', () => {
  it('should convert a number to 2 byte array', () => {
    const n = 1234
    const res = util.to2Bytes(n)

    expect(res).to.eql([4, 210])
  })
})

describe('from2Bytes', () => {
  it('should convert a 2 byte array to number', () => {
    const arr = [4, 210]
    const res = util.from2Bytes(arr)

    expect(res).to.eql(1234)
  })
})

describe('bin2Hex', () => {
  it('should convert an array buffer to a hex encoded string', () => {
    const buf = new Uint8Array([99, 111, 110, 118, 101, 114, 116, 32, 109, 101])
    const res = util.bin2Hex(buf)

    expect(res).to.equal('636F6E76657274206D65')
  })
})

describe('hex2bin', () => {
  it('should convert a hex encoded string to array buffer', () => {
    const s = '636F6E76657274206D65'
    const res = util.hex2bin(s)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([99, 111, 110, 118, 101, 114, 116, 32, 109, 101]))
  })
})

describe('mapError', () => {
  it('should throw an error if the provided function throws', () => {
    const f = () => { throw new Error() }
    const err = new Error('msg')

    expect(() => util.mapError(f, err)).to.throw(err)
  })
  it('should not throw otherwise', () => {
    expect(() => util.mapError(() => 0, new Error())).to.not.throw()
  })
})

describe('mapErrorAsync', () => {
  it('should throw an error if the provided function throws', () => {
    const err = new Error('msg')

    return expect(util.mapErrorAsync(() => new Promise(_ => { throw new Error() }), err)).to.eventually.be.rejectedWith(err)
  })
  it('should not throw otherwise', () => {
    return expect(util.mapErrorAsync(() => Promise.resolve(0), new Error())).to.eventually.not.be.rejected
  })
})