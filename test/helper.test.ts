import * as chai from 'chai'
import * as helper from '../src/helper'

chai.use(require('chai-as-promised'))

const { expect } = chai

describe('str2ab', () => {
  it('should convert a string to array buffer', () => {
    const s = 'convert me'
    const res = helper.str2ab(s)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([99, 111, 110, 118, 101, 114, 116, 32, 109, 101]))
  })
})

describe('arr2str', () => {
  it('should convert an array buffer to string', () => {
    const buf = new Uint8Array([99, 111, 110, 118, 101, 114, 116, 32, 109, 101]).buffer
    const res = helper.ab2str(buf)

    expect(res).to.equal('convert me')
  })
})

describe('b642arr', () => {
  it('should convert a base 64 string to byte array', () => {
    const b64str = 't9wS6Bif9MefxtaEer1GTg=='
    const res = helper.b642arr(b64str)

    expect(res).to.eql(new Uint8Array([183, 220, 18, 232, 24, 159, 244, 199, 159, 198, 214, 132, 122, 189, 70, 78]))
  })
})

describe('arr2b64', () => {
  it('should convert a byte array to base 64 string', () => {
    const arr = new Uint8Array([183, 220, 18, 232, 24, 159, 244, 199, 159, 198, 214, 132, 122, 189, 70, 78])
    const res = helper.arr2b64(arr)

    expect(res).to.equal('t9wS6Bif9MefxtaEer1GTg==')
  })
})

describe('concat', () => {
  it('should concatenate two Uint8Array objects', () => {
    const arr1 = new Uint8Array([1, 2, 3, 4])
    const arr2 = new Uint8Array([5, 6, 7, 8])
    const res = helper.concat(arr1, arr2)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
  })
  it('should concatenate two ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3, 4]).buffer
    const arr2 = new Uint8Array([5, 6, 7, 8]).buffer
    const res = helper.concat(arr1, arr2)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
  })
  it('should concatenate Uint8Array and ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3, 4])
    const arr2 = new Uint8Array([5, 6, 7, 8]).buffer
    const res = helper.concat(arr1, arr2)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
  })
  it('should concatenate three Uint8Array objects', () => {
    const arr1 = new Uint8Array([1, 2, 3])
    const arr2 = new Uint8Array([4, 5, 6])
    const arr3 = new Uint8Array([7, 8, 9])
    const res = helper.concat3(arr1, arr2, arr3)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
  })
  it('should concatenate three ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3]).buffer
    const arr2 = new Uint8Array([4, 5, 6]).buffer
    const arr3 = new Uint8Array([7, 8, 9]).buffer
    const res = helper.concat3(arr1, arr2, arr3)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
  })
  it('should concatenate mix of Uint8Array and ArrayBuffer objects', () => {
    const arr1 = new Uint8Array([1, 2, 3]).buffer
    const arr2 = new Uint8Array([4, 5, 6])
    const arr3 = new Uint8Array([7, 8, 9]).buffer
    const res = helper.concat3(arr1, arr2, arr3)

    expect(new Uint8Array(res)).to.eql(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
  })
})

describe('getInt64Bytes', () => {
  it('should convert a number to byte array', () => {
    const n = 123456789
    const res = helper.getInt64Bytes(n)

    expect(res).to.eql([0, 0, 0, 0, 7, 91, 205, 21])
  })
})

describe('intFromBytes', () => {
  it('should convert a byte array to number', () => {
    const arr = [0, 0, 0, 0, 7, 91, 205, 21]
    const res = helper.intFromBytes(arr)

    expect(res).to.eql(123456789)
  })
})

describe('retrow', () => {
  it('should throw if provided function throws', () => {
    const f = () => { throw new Error() }
    const err = new Error('msg')

    expect(() => helper.rethrow(f, err)).to.throw(err)
  })
  it('should not throw otherwise', () => {
    expect(() => helper.rethrow(() => 0, new Error())).to.not.throw()
  })
})

describe('rethrowPromise', () => {
  it('should throw if provided function throws', () => {
    const err = new Error('msg')

    return expect(helper.rethrowPromise(() => new Promise(_ => { throw new Error() }), err)).to.eventually.be.rejectedWith(err)
  })
  it('should not throw otherwise', () => {
    return expect(helper.rethrowPromise(() => Promise.resolve(0), new Error())).to.eventually.not.be.rejected
  })
})