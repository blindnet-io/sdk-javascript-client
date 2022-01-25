import * as chai from 'chai'
import { getLocal } from 'mockttp'

import { Blindnet } from '../src'
import { TestKeyStore } from './test_interfaces'

const mockServer = getLocal()

chai.use(require('chai-as-promised'))
const { expect } = chai

const pass1 = 'p4ss'
const new_pass1 = '@#&*@'
const pass2 = '12345678'

const alice = 'alice'
const bob = 'bob'

describe('Blindnet', () => {
  beforeEach(() => mockServer.start(8088))
  afterEach(() => mockServer.stop())

  // db
  type UserData = {
    publicEncryptionKey: string,
    publicSigningKey: string,
    encryptedPrivateEncryptionKey: string,
    encryptedPrivateSigningKey: string,
    keyDerivationSalt: string,
    signedJwt: string,
    signedPublicEncryptionKey: string
  }
  let users: { [key: string]: UserData } = {}
  let keys: { [key: string]: { userID: string, encryptedSymmetricKey: string }[] } = {}
  let datas: { [key: string]: ArrayBuffer } = {}

  const dataIdString = '89acef54-e1a3-437c-bb24-82b08470a172'
  const dataIdFile = '9106d3ae-c164-42e9-97f6-ed3114098e27'
  const dataIdBinary = '4ee6d347-a985-4bf9-a239-252a8c026c80'
  const dataIdJson = '7aed76e9-700c-44be-b93c-260ae90b2949'
  const dataIdMeta1 = '11111111-1111-1111-1111-111111111111'
  const dataIdMeta2 = '11111111-1111-1111-1111-111111111112'
  const dataIdMulti = '11111111-1111-1111-1111-111111111113'

  const keyStore = new TestKeyStore()
  const blindnet = Blindnet.initCustomKeyStore('', keyStore, 'http://localhost:8088')

  const connect = async (user: string, pass: string) => {
    await mockServer.get("/api/v1/keys/me").thenJson(200, users[user])
    await blindnet.connect(pass)
  }
  const connectAlice = (pass: string = pass1) => connect(alice, pass)
  const connectBob = connect.bind(this, bob, pass2)

  it('should derive the secrets', async () => {
    const derived = await Blindnet.deriveSecrets(pass1)

    expect(derived).to.eql({
      'appSecret': 'Bvlw01zDbQgBpmZeoQkrJVk9HHs+yZCc7NtWeb/+yMA=',
      'blindnetSecret': 'RrP5TZ6exqibW9UkyJEFxB6RXHB7AMUb/BeNrAwcPP8='
    })
  })

  describe('connect', () => {

    it('should fail with AuthenticationError if a bad or expired token is provided', async () => {
      await mockServer.get("/api/v1/keys/me").thenReply(401, '')
      return expect(blindnet.connect(pass1)).to.eventually.be.rejected.and.have.property('code', 'blindnet.authentication')
    })

    it('should fail with BlindnetServiceError if there was a server error', async () => {
      await mockServer.get("/api/v1/keys/me").thenReply(400, '')

      return expect(blindnet.connect(pass1)).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should register a new user alice', async () => {
      await mockServer.get("/api/v1/keys/me").thenReply(400)
      await mockServer.post("/api/v1/users")
        // @ts-ignore
        .matching(req => { users[alice] = req.body.json; return true })
        .thenReply(200, '{}')

      await blindnet.connect(pass1)
    })

    it('should connect alice', async () => {
      await connectAlice()
    })

    it('should fail with SecretError if a wrong password is provided', async () => {
      await mockServer.get("/api/v1/keys/me").thenJson(200, users[alice])

      return expect(blindnet.connect('asd')).to.eventually.be.rejected.and.have.property('code', 'blindnet.secret')
    })

    it('should register a new user bob', async () => {
      await mockServer.get("/api/v1/keys/me").thenReply(400)
      await mockServer.post("/api/v1/users")
        // @ts-ignore
        .matching(req => { users[bob] = req.body.json; return true })
        .thenReply(200, '{}')

      await blindnet.connect(pass2)
    })
  })

  describe('encrypt', () => {
    it('should fail if no data is provided', () => {
      return expect(blindnet.capture(null).forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.data_format')
    })

    it('should fail if metadata is not a JSON object', () => {
      // @ts-ignore
      return expect(blindnet.capture('').withMetadata(1).forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.data_format')
    })

    it('should fail if capture destination is not specified', () => {
      return expect(blindnet.capture('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.not_encryptable')
    })

    it('should fail if userIds is not an array', () => {
      // @ts-ignore
      return expect(blindnet.capture('').forUsers(1).encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.not_encryptable')
    })

    it('should fail if groupId is not a string', () => {
      // @ts-ignore
      return expect(blindnet.capture('').forGroup(1).encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.not_encryptable')
    })

    it('should fail if data is null', () => {
      return expect(blindnet.capture(null).forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.data_format')
    })

    it('should fail if no users are returned from the server', async () => {
      await mockServer.post("/api/v1/keys").thenJson(200, [])
      return expect(blindnet.capture('').forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.not_encryptable')
    })

    it('should fail with AuthenticationError if a bad or expired token is provided', async () => {
      await mockServer.post("/api/v1/keys").thenReply(401)
      await expect(blindnet.capture('').forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.authentication')

      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])
      await mockServer.post("/api/v1/documents").thenReply(401)
      await expect(blindnet.capture('').forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.authentication')
    })

    it('should fail with BlindnetServiceError for server errors', async () => {
      await mockServer.post("/api/v1/keys").thenReply(400)
      await expect(blindnet.capture('').forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')

      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])
      await mockServer.post("/api/v1/documents").thenReply(404)
      await expect(blindnet.capture('').forUser('').encrypt()).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should encrypt string', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdString] = b; return true }))
        .thenReply(200, `"${dataIdString}"`)

      const { dataId, encryptedData } = await blindnet.capture('hello').forGroup('').encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdString)
      expect(encryptedData.byteLength).to.eql(94)
    })

    it('should encrypt file', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdFile] = b; return true }))
        .thenReply(200, `"${dataIdFile}"`)

      const { dataId, encryptedData } = await blindnet.capture(new File(['hello'], 'asd')).forUsers([]).encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdFile)
      expect(encryptedData.byteLength).to.eql(105)
    })

    it('should encrypt binary data', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdBinary] = b; return true }))
        .thenReply(200, `"${dataIdBinary}"`)

      const { dataId, encryptedData } = await blindnet.capture(new Uint8Array([1, 2, 3]).buffer).forUser('').encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdBinary)
      expect(encryptedData.byteLength).to.eql(92)
    })

    it('should encrypt JSON', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdJson] = b; return true }))
        .thenReply(200, `"${dataIdJson}"`)

      const { dataId, encryptedData } = await blindnet.capture({ x: 1, y: { z: [1, 2, 3] } }).forUser('').encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdJson)
      expect(encryptedData.byteLength).to.eql(112)
    })

    it('should encrypt empty metadata', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdMeta1] = b; return true }))
        .thenReply(200, `"${dataIdMeta1}"`)

      const { dataId, encryptedData } = await blindnet.capture('hello').withMetadata({}).forUser('').encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdMeta1)
      expect(encryptedData.byteLength).to.eql(94)
    })

    it('should encrypt metadata', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [{ publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice }])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdMeta2] = b; return true }))
        .thenReply(200, `"${dataIdMeta2}"`)

      const metadata = { x: '', y: [{ z: true }, 2], q: { w: '' } }

      const { dataId, encryptedData } = await blindnet.capture('hello').withMetadata(metadata).forUser('').encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdMeta2)
      expect(encryptedData.byteLength).to.eql(132)
    })

    it('should encrypt string for multiple users', async () => {
      await mockServer.post("/api/v1/keys")
        .thenJson(200, [
          { publicEncryptionKey: users[alice].publicEncryptionKey, userID: alice },
          { publicEncryptionKey: users[bob].publicEncryptionKey, userID: bob }
        ])

      await mockServer.post("/api/v1/documents")
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => { keys[dataIdMulti] = b; return true }))
        .thenReply(200, `"${dataIdMulti}"`)

      const { dataId, encryptedData } = await blindnet.capture('hello to two').forUser('').encrypt()
      datas[dataId] = encryptedData

      expect(dataId).to.eql(dataIdMulti)
      expect(encryptedData.byteLength).to.eql(101)
    })
  })

  describe('decrypt', () => {
    it('should throw an error if local keys are missing', async () => {
      await connectAlice()
      keyStore.clear()
      return expect(blindnet.decrypt(datas[dataIdString])).to.eventually.be.rejected.and.have.property('code', 'blindnet.user_not_initialized')
    })

    it('should throw an error if data id can\'t be decoded', async () => {
      await connectAlice()
      return expect(blindnet.decrypt(new ArrayBuffer(0))).to.eventually.be.rejected.and.have.property('code', 'blindnet.data_format')
    })

    it('should throw an error if data is in wrong format', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdString}`)
        .thenReply(200, `"${keys[dataIdString].find(k => k.userID === alice).encryptedSymmetricKey}"`)
      await connectAlice()
      return expect(blindnet.decrypt(datas[dataIdString].slice(0, 40))).to.eventually.be.rejected.and.have.property('code', 'blindnet.encryption')
    })

    it('should throw an error if a blindnet server error occurs', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdString}`).thenReply(500)
      await connectAlice()
      return expect(blindnet.decrypt(datas[dataIdString].slice(0, 40))).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should decrypt string', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdString}`)
        .thenReply(200, `"${keys[dataIdString].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData = datas[dataIdString]
      const { data, dataType } = await blindnet.decrypt(encryptedData)

      expect(dataType.type).to.eq('String')
      expect(data).to.eql('hello')
    })

    it('should decrypt file', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdFile}`)
        .thenReply(200, `"${keys[dataIdFile].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData = datas[dataIdFile]
      const { data, dataType } = await blindnet.decrypt(encryptedData)

      const text = await (data as File).text()
      const fileName = (data as File).name

      expect(dataType.type).to.eq('File')
      expect(text).to.eql('hello')
      expect(fileName).to.eq('asd')
    })

    it('should decrypt binary data', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdBinary}`)
        .thenReply(200, `"${keys[dataIdBinary].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData = datas[dataIdBinary]
      const { data, dataType } = await blindnet.decrypt(encryptedData)

      expect(dataType.type).to.eq('Binary')
      // @ts-ignore
      expect(new Uint8Array(data)).to.eql(new Uint8Array([1, 2, 3]))
    })

    it('should decrypt JSON', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdJson}`)
        .thenReply(200, `"${keys[dataIdJson].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData = datas[dataIdJson]
      const { data, dataType } = await blindnet.decrypt(encryptedData)

      expect(dataType.type).to.eq('Json')
      expect(data).to.eql({ x: 1, y: { z: [1, 2, 3] } })
    })

    it('should decrypt empty metadata', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdMeta1}`)
        .thenReply(200, `"${keys[dataIdMeta1].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData = datas[dataIdMeta1]
      const { metadata } = await blindnet.decrypt(encryptedData)

      expect(metadata).to.eql({})
    })

    it('should decrypt metadata', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdMeta2}`)
        .thenReply(200, `"${keys[dataIdMeta2].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData = datas[dataIdMeta2]
      const { metadata } = await blindnet.decrypt(encryptedData)

      const expected = { x: '', y: [{ z: true }, 2], q: { w: '' } }

      expect(metadata).to.eql(expected)
    })

    it('should decrypt string encrypted for multiple users', async () => {
      await mockServer.get(`/api/v1/documents/keys/${dataIdMulti}`)
        .thenReply(200, `"${keys[dataIdMulti].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      await connectAlice()

      const encryptedData1 = datas[dataIdMulti]
      const { data: data1, dataType: dataType1 } = await blindnet.decrypt(encryptedData1)

      expect(dataType1.type).to.eq('String')
      expect(data1).to.eql('hello to two')


      await mockServer.get(`/api/v1/documents/keys/${dataIdMulti}`)
        .thenReply(200, `"${keys[dataIdMulti].find(k => k.userID === bob).encryptedSymmetricKey}"`)

      await connectBob()

      const encryptedData2 = datas[dataIdMulti]
      const { data: data2, dataType: dataType2 } = await blindnet.decrypt(encryptedData2)

      expect(dataType2.type).to.eq('String')
      expect(data2).to.eql('hello to two')
    })
  })

  describe('decryptMany', () => {

    it('should throw an error if local keys are missing', async () => {
      await connectAlice()
      keyStore.clear()
      return expect(blindnet.decryptMany([])).to.eventually.be.rejected.and.have.property('code', 'blindnet.user_not_initialized')
    })

    it('should throw an error if data id can\'t be decoded', async () => {
      await connectAlice()
      return expect(blindnet.decryptMany([new ArrayBuffer(0)])).to.eventually.be.rejected.and.have.property('code', 'blindnet.data_format')
    })

    it('should throw an error if a blindnet server error occurs', async () => {
      await mockServer.post(`/api/v1/documents/keys`).thenReply(500)

      await connectAlice()
      return expect(blindnet.decryptMany(Object.values(datas))).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should throw an error if a wrong number of keys is returned from the server', async () => {
      await mockServer.post(`/api/v1/documents/keys`).thenJson(200, [])

      await connectAlice()
      return expect(blindnet.decryptMany(Object.values(datas))).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should throw an error if some of data is in wrong format', async () => {
      await mockServer.post(`/api/v1/documents/keys`)
        .thenJson(200, Object.entries(keys).map(d => ({ documentID: d[0], encryptedSymmetricKey: d[1].find(dd => dd.userID === alice).encryptedSymmetricKey })))

      const d = Object.values(datas)
      d[1] = d[1].slice(0, 40)
      await connectAlice()
      return expect(blindnet.decryptMany(d)).to.eventually.be.rejected.and.have.property('code', 'blindnet.encryption')
    })

    it('should decrypt multiple encrypted data', async () => {
      await mockServer.post(`/api/v1/documents/keys`)
        .thenJson(200, Object.entries(keys).map(d => ({ documentID: d[0], encryptedSymmetricKey: d[1].find(dd => dd.userID === alice).encryptedSymmetricKey })))

      await connectAlice()

      const result = await blindnet.decryptMany(Object.values(datas))

      expect(result[0].dataType.type).to.eq('String')
      expect(result[0].data).to.eql('hello')
      expect(result[0].metadata).to.eql({})

      const text = await (result[1].data as File).text()
      expect(result[1].dataType.type).to.eq('File')
      expect(text).to.eql('hello')
      expect((result[1].data as File).name).to.eq('asd')

      expect(result[2].dataType.type).to.eq('Binary')
      // @ts-ignore
      expect(new Uint8Array(result[2].data)).to.eql(new Uint8Array([1, 2, 3]))

      expect(result[3].dataType.type).to.eq('Json')
      expect(result[3].data).to.eql({ x: 1, y: { z: [1, 2, 3] } })

      expect(result[4].metadata).to.eql({})
      expect(result[5].metadata).to.eql({ x: '', y: [{ z: true }, 2], q: { w: '' } })

      expect(result[6].dataType.type).to.eq('String')
      expect(result[6].data).to.eql('hello to two')
    })
  })

  describe('giveAccess', () => {
    it('should throw an error if local keys are missing', async () => {
      await connectAlice()
      keyStore.clear()
      return expect(blindnet.giveAccess('')).to.eventually.be.rejected.and.have.property('code', 'blindnet.user_not_initialized')
    })

    it('should throw an error if obtaining a user key from the server failed', async () => {
      await mockServer.get(`/api/v1/keys/bob`).thenReply(500)
      await connectAlice()
      return expect(blindnet.giveAccess(bob)).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should throw an error if obtaining the data keys from the server failed', async () => {
      await mockServer.get(`/api/v1/keys/bob`)
        .thenJson(200, { publicEncryptionKey: users[bob].publicEncryptionKey, publicSigningKey: users[bob].publicSigningKey })
      await mockServer.get(`/api/v1/documents/keys`).thenReply(500)
      await connectAlice()

      return expect(blindnet.giveAccess(bob)).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should throw an error if storing new keys failed', async () => {
      await mockServer.get(`/api/v1/keys/bob`)
        .thenJson(200, { publicEncryptionKey: users[bob].publicEncryptionKey, publicSigningKey: users[bob].publicSigningKey })
      await mockServer.get(`/api/v1/documents/keys`)
        .thenJson(200, [
          { documentID: dataIdString, encryptedSymmetricKey: keys[dataIdString][0].encryptedSymmetricKey },
          { documentID: dataIdBinary, encryptedSymmetricKey: keys[dataIdBinary][0].encryptedSymmetricKey },
          { documentID: dataIdMeta2, encryptedSymmetricKey: keys[dataIdMeta2][0].encryptedSymmetricKey }
        ])
      await mockServer.put('/api/v1/documents/keys/user/bob').thenReply(500)

      await connectAlice()

      return expect(blindnet.giveAccess(bob)).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should successfully give access to another user', async () => {
      let bobKey0, bobKey1, bobKey2

      await mockServer.get(`/api/v1/keys/bob`)
        .thenJson(200, { publicEncryptionKey: users[bob].publicEncryptionKey, publicSigningKey: users[bob].publicSigningKey })
      await mockServer.get(`/api/v1/documents/keys`)
        .thenJson(200, [
          { documentID: dataIdString, encryptedSymmetricKey: keys[dataIdString][0].encryptedSymmetricKey },
          { documentID: dataIdBinary, encryptedSymmetricKey: keys[dataIdBinary][0].encryptedSymmetricKey },
          { documentID: dataIdMeta2, encryptedSymmetricKey: keys[dataIdMeta2][0].encryptedSymmetricKey }
        ])
      await mockServer.put('/api/v1/documents/keys/user/bob')
        // @ts-ignore
        .matching(req => req.body.getJson().then(b => {
          bobKey0 = b[0].encryptedSymmetricKey;
          bobKey1 = b[1].encryptedSymmetricKey;
          bobKey2 = b[2].encryptedSymmetricKey;
          return true
        }))
        .thenReply(200, 'true')

      await connectAlice()

      await blindnet.giveAccess(bob)


      await mockServer.get(`/api/v1/documents/keys/${dataIdString}`)
        .thenJson(200, bobKey0)

      await connectBob()

      const encryptedData = datas[dataIdString]
      const { data, dataType } = await blindnet.decrypt(encryptedData)

      expect(dataType.type).to.eq('String')
      expect(data).to.eql('hello')


      const d = [datas[dataIdString], datas[dataIdBinary], datas[dataIdMeta2], datas[dataIdMulti]]

      await mockServer.post(`/api/v1/documents/keys`)
        .thenJson(200, [
          { documentID: dataIdString, encryptedSymmetricKey: bobKey0 },
          { documentID: dataIdBinary, encryptedSymmetricKey: bobKey1 },
          { documentID: dataIdMeta2, encryptedSymmetricKey: bobKey2 },
          { documentID: dataIdMulti, encryptedSymmetricKey: keys[dataIdMulti].find(k => k.userID === bob).encryptedSymmetricKey }
        ])

      await connectBob()

      const result = await blindnet.decryptMany([datas[dataIdString], datas[dataIdBinary], datas[dataIdMeta2], datas[dataIdMulti]])

      expect(result[0].dataType.type).to.eq('String')
      expect(result[0].data).to.eql('hello')
      expect(result[0].metadata).to.eql({})

      expect(result[1].dataType.type).to.eq('Binary')
      // @ts-ignore
      expect(new Uint8Array(result[1].data)).to.eql(new Uint8Array([1, 2, 3]))

      expect(result[2].metadata).to.eql({ x: '', y: [{ z: true }, 2], q: { w: '' } })

      expect(result[3].dataType.type).to.eq('String')
      expect(result[3].data).to.eql('hello to two')
    })
  })

  describe('changeSecret', () => {
    it('should throw an error if local keys are missing', async () => {
      await connectAlice()
      keyStore.clear()
      return expect(blindnet.changeSecret('')).to.eventually.be.rejected.and.have.property('code', 'blindnet.user_not_initialized')
    })

    it('should throw an error if storing the new encrypted keys failed', async () => {
      await mockServer.put(`/api/v1/keys/me`).thenReply(500)
      await connectAlice()
      return expect(blindnet.changeSecret(new_pass1)).to.eventually.be.rejected.and.have.property('code', 'blindnet.service')
    })

    it('should successfully change a secret', async () => {
      await mockServer.put(`/api/v1/keys/me`)
        .matching(req => { users[alice] = { ...users[alice], ...req.body.json }; return true })
        .thenReply(200, 'true')

      await connectAlice(pass1)
      await blindnet.changeSecret(new_pass1)

      blindnet.disconnect()
      await connectAlice(new_pass1)


      await mockServer.get(`/api/v1/documents/keys/${dataIdString}`)
        .thenReply(200, `"${keys[dataIdString].find(k => k.userID === alice).encryptedSymmetricKey}"`)

      const encryptedData = datas[dataIdString]
      const { data, dataType } = await blindnet.decrypt(encryptedData)

      expect(dataType.type).to.eq('String')
      expect(data).to.eql('hello')
    })
  })
})
