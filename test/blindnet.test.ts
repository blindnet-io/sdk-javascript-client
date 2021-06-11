import * as chai from 'chai'
import * as mocha from 'mocha'
import * as cc from 'chai-as-promised'

import * as util from '../src/util'
import * as cryptoUtil from '../src/cryptoUtil'
import blindnet from '../src'
import { TestKeyStore, TestService } from './test_interfaces'

chai.use(require('chai-as-promised'))
const { expect } = chai

const { Blindnet } = blindnet

const jwt1 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMSIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.SWD8ihR-QJDcvBvBWjzrOKrGNTUd2ZSkIIlr2Il4WkA'
const jwt2 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMiIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.RbJ064ATXYpBp5A1li2KlGr7wVnGLi_JsXll6F0X81Q'
const jwt3 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMyIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.oa58XT_iiRInXVbkkdQNE-hHWd1LTGok5zQ14nKA1Co'
const short_jwt = ''

const pass1 = 'p4ss'
const new_pass1 = '@#&*@'
const new_pass2 = '483029843902'
const pass2 = '12345678'
const pass3 = 'p4ssW0rD'

describe('Blindnet', () => {
  // db
  let users = {}
  let docKeys = {}

  const testKS = new TestKeyStore()
  const testS = new TestService(jwt1, users, docKeys)
  const blindnet = Blindnet.initTest(testS, testKS)

  it('should derive the secrets', async () => {
    const derived = await Blindnet.deriveSecrets(pass1)

    expect(derived).to.eql({
      'appSecret': 'Bvlw01zDbQgBpmZeoQkrJVk9HHs+yZCc7NtWeb/+yMA=',
      'blindnetSecret': 'RrP5TZ6exqibW9UkyJEFxB6RXHB7AMUb/BeNrAwcPP8='
    })
  })

  it('should fail to encrypt if data format is not supported', () => {
    expect(Object.keys(users).length).to.equal(0)

    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    return expect(blindnet.encrypt(null)).to.eventually.be.rejected.and.have.property('code', 9)
  })

  it('should fail to encrypt if metadata is not an object', () => {
    expect(Object.keys(users).length).to.equal(0)

    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    // @ts-ignore
    return expect(blindnet.encrypt('', 1)).to.eventually.be.rejected.and.have.property('code', 9)
  })

  it('should fail to encrypt a document if no users are registered', () => {
    expect(Object.keys(users).length).to.equal(0)

    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    return expect(blindnet.encrypt(util.str2ab(''))).to.eventually.be.rejected.and.have.property('code', 6)
  })

  it('should register a new user and initialize the keys locally', async () => {
    expect(users[jwt1]).to.equal(undefined)
    expect(testKS.store).to.eql({})
    await blindnet.connect(pass1)
    expect(Object.keys(testKS.store).length).to.equal(5)
    expect(users[jwt1].user_id).to.equal('user1')
  })

  it('should fail with AuthenticationError if a wrong JWT is provided', () => {
    const blindnet = Blindnet.initTest(new TestService(jwt1, {}, {}, false, true), testKS)
    return expect(blindnet.connect(pass1)).to.eventually.be.rejected.and.have.property('code', 1)
  })

  it('should fail with BlindnetServiceError for back-end errors', () => {
    const blindnet = Blindnet.initTest(new TestService(jwt1, {}, {}, true, false), testKS)
    return expect(blindnet.connect(pass1)).to.eventually.be.rejected.and.have.property('code', 5)
  })

  it('should fail with PasswordError if a wrong password is provided for existing user', () => {
    return expect(blindnet.connect('wrong_pass')).to.eventually.be.rejected.and.have.property('code', 3)
  })

  it('should login an existing user and decrypt and store the keys locally', async () => {
    expect(users[jwt1].user_id).to.equal('user1')
    await blindnet.connect(pass1)
  })

  it('should register the second user', async () => {
    await testKS.clear()
    const testS = new TestService(jwt2, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    expect(users[jwt2]).to.equal(undefined)
    await blindnet.connect(pass2)
    expect(users[jwt2].user_id).to.equal('user2')
  })

  let docId1, encDoc1

  it('should encrypt a document as a byte array', async () => {
    await testKS.clear()
    expect(Object.keys(docKeys).length).to.equal(0)

    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    const encryptedData = await blindnet.encrypt(util.str2ab('This is the document content'), { "doc_name": "passport.pdf" })
    const dataId = util.ab2str(encryptedData.encryptedData.slice(0, 36))
    docId1 = dataId
    encDoc1 = encryptedData.encryptedData

    expect(docKeys[dataId].map(x => x.userID)).to.eql(['user1', 'user2'])
  })

  let fileId1, encFile1

  it('should encrypt a document as a file', async () => {
    await testKS.clear()

    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    const encryptedData = await blindnet.encrypt(new File(['hello'], 'hello.txt'))
    const dataId = util.ab2str(encryptedData.encryptedData.slice(0, 36))
    fileId1 = dataId
    encFile1 = encryptedData.encryptedData
  })

  it('should decrypt a document as a file', async () => {
    await blindnet.connect(pass1)

    const decData = await blindnet.decrypt(encFile1)

    const data = decData.data as File

    expect(data.name).to.equal('hello.txt')
    expect(decData.metadata).to.eql({ dataType: { type: 'FILE', name: 'hello.txt' } })
  })

  let textId1, encText1

  it('should encrypt a text', async () => {
    await testKS.clear()

    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    const encryptedData = await blindnet.encrypt('encrypt me !!', { hello: 420 })
    const dataId = util.ab2str(encryptedData.encryptedData.slice(0, 36))
    textId1 = dataId
    encText1 = encryptedData.encryptedData
  })

  it('should decrypt a text', async () => {
    await blindnet.connect(pass1)

    const decData = await blindnet.decrypt(encText1)

    const data = decData.data as string

    expect(data).to.equal('encrypt me !!')
    expect(decData.metadata).to.eql({ dataType: { type: 'STRING' }, hello: 420 })
  })

  it('should register the third user', async () => {
    await testKS.clear()
    const testS = new TestService(jwt3, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    expect(users[jwt3]).to.equal(undefined)
    await blindnet.connect(pass3)
    expect(users[jwt3].user_id).to.equal('user3')
  })

  it('should fail to decrypt if a user is not initialized locally', async () => {
    await testKS.clear()
    return expect(blindnet.decrypt(encDoc1)).to.eventually.be.rejected.and.have.property('code', 4)
  })

  it('should fail to decrypt if a user does not have access to a documet', async () => {
    const testS = new TestService(jwt3, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)
    await blindnet.connect(pass3)

    return expect(blindnet.decrypt(encDoc1)).to.eventually.be.rejected.and.have.property('code', 7)
  })

  it('should fail to decrypt the data if the data has been tempered with', async () => {
    await blindnet.connect(pass1)

    return expect(blindnet.decrypt(util.concat(encDoc1, new Uint8Array([1, 2, 3])))).to.eventually.be.rejected.and.have.property('code', 4)
  })

  it('should fail to decrypt the data if the local private key is bad', async () => {
    await blindnet.connect(pass1)

    const newKeys = await cryptoUtil.generateRandomRSAKeyPair()

    await testKS.storeKey('private', newKeys.privateKey)

    return expect(blindnet.decrypt(util.concat(encDoc1, new Uint8Array([1, 2, 3])))).to.eventually.be.rejected.and.have.property('code', 4)
  })

  it('should decrypt the data as byte array', async () => {
    await blindnet.connect(pass1)

    const decData = await blindnet.decrypt(encDoc1)

    const data = util.ab2str(decData.data as ArrayBuffer)

    expect(data).to.equal('This is the document content')
    expect(decData.metadata).to.eql({ dataType: { type: 'BYTES' }, doc_name: 'passport.pdf' })
  })

  let docId2, encDoc2

  it('should encrypt the second data', async () => {
    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    const encryptedData = await blindnet.encrypt(util.str2ab('This is the second document'))
    const dataId = util.ab2str(encryptedData.encryptedData.slice(0, 36))
    docId2 = dataId
    encDoc2 = encryptedData.encryptedData

    expect(docKeys[dataId].map(x => x.userID)).to.eql(['user1', 'user2', 'user3'])
  })

  it('should decrypt the second data', async () => {
    await blindnet.connect(pass1)

    const decData = await blindnet.decrypt(encDoc2)

    const data = util.ab2str(decData.data as ArrayBuffer)
    const metadata = decData.metadata

    expect(data).to.equal('This is the second document')
    expect(metadata).to.eql({ dataType: { type: 'BYTES' } })
  })

  it('should encrypt the empty data', async () => {
    const testS = new TestService(short_jwt, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)

    const encryptedData = await blindnet.encrypt(new ArrayBuffer(0))
    const dataId = util.ab2str(encryptedData.encryptedData.slice(0, 36))
    encDoc2 = encryptedData.encryptedData

    expect(docKeys[dataId].map(x => x.userID)).to.eql(['user1', 'user2', 'user3'])
  })

  it('should decrypt the empty data', async () => {
    await blindnet.connect(pass1)

    const decData = await blindnet.decrypt(encDoc2)

    expect((decData.data as ArrayBuffer).byteLength).to.equal(0)
    expect(decData.metadata).to.eql({ dataType: { type: 'BYTES' } })
  })

  it('should fail giving access to an unregistered user', async () => {
    await blindnet.connect(pass1)
    return expect(blindnet.giveAccess('unregistered')).to.eventually.be.rejected.and.have.property('code', 8)
  })

  it('should give access to the third user', async () => {
    await blindnet.connect(pass1)

    await blindnet.giveAccess('user3')

    expect(docKeys[docId1].map(x => x.userID)).to.eql(['user1', 'user2', 'user3'])
  })

  it('should decrypt the first data after access has been given', async () => {
    const testS = new TestService(jwt3, users, docKeys)
    const blindnet = Blindnet.initTest(testS, testKS)
    await blindnet.connect(pass3)

    const decData = await blindnet.decrypt(encDoc1)

    const data = util.ab2str(decData.data as ArrayBuffer)
    const metadata = decData.metadata

    expect(data).to.equal('This is the document content')
    expect(metadata).to.eql({ dataType: { type: 'BYTES' }, doc_name: 'passport.pdf' })
  })

  it('should update users password', async () => {
    await blindnet.connect(pass1)

    const old_esk = users[jwt1].e_enc_SK
    const old_ssk = users[jwt1].e_sign_SK
    await blindnet.changeSecret(new_pass1)
    const new_esk = users[jwt1].e_enc_SK
    const new_ssk = users[jwt1].e_sign_SK

    expect(old_esk).to.not.equal(new_esk)
    expect(old_ssk).to.not.equal(new_ssk)
  })

  it('should fail to login with the old password after password change', () => {
    return expect(blindnet.connect(pass1)).to.eventually.be.rejected.and.have.property('code', 3)
  })

  it('should decrypt the data after password change', async () => {
    await blindnet.connect(new_pass1)

    const decData = await blindnet.decrypt(encDoc1)

    const data = util.ab2str(decData.data as ArrayBuffer)
    const metadata = decData.metadata

    expect(data).to.equal('This is the document content')
    expect(metadata).to.eql({ dataType: { type: 'BYTES' }, doc_name: 'passport.pdf' })
  })

  it('should update users password with old password provided', async () => {
    await blindnet.connect(new_pass1)

    const old_esk = users[jwt1].e_enc_SK
    const old_ssk = users[jwt1].e_sign_SK
    await blindnet.changeSecret(new_pass2, new_pass1)
    const new_esk = users[jwt1].e_enc_SK
    const new_ssk = users[jwt1].e_sign_SK

    expect(old_esk).to.not.equal(new_esk)
    expect(old_ssk).to.not.equal(new_ssk)
  })

  it('should fail to login with the old password after password change', () => {
    return expect(blindnet.connect(new_pass1)).to.eventually.be.rejected.and.have.property('code', 3)
  })

  it('should decrypt the data after password change', async () => {
    await blindnet.connect(new_pass2)

    const decData = await blindnet.decrypt(encDoc1)

    const data = util.ab2str(decData.data as ArrayBuffer)
    const metadata = decData.metadata

    expect(data).to.equal('This is the document content')
    expect(metadata).to.eql({ dataType: { type: 'BYTES' }, doc_name: 'passport.pdf' })
  })

})
