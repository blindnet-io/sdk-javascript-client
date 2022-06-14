const path = require('path')
import { test, expect, Page } from '@playwright/test'
import * as crypto from 'node:crypto'

import * as Blindnet from '../src'

const appKey = ''
const appId = ''
const endpoint = ''

type Data = {
  key: string,
  appId: string,
  endpoint: string,

  group1: string,
  group2: string,
  user1: string,
  user2: string,
  user3: string,
  user4: string,

  pass1a: string,
  pass1b: string,
  pass2: string,
  pass3: string
  pass4: string
  pass5: string
}

let data: Data = {
  key: appKey,
  appId: appId,
  endpoint: endpoint,

  group1: `test-group-${crypto.randomUUID()}`,
  group2: `test-group-${crypto.randomUUID()}`,
  user1: `test-${crypto.randomUUID()}`,
  user2: `test-${crypto.randomUUID()}`,
  user3: `test-${crypto.randomUUID()}`,
  user4: `test-${crypto.randomUUID()}`,

  pass1a: 'pass1a',
  pass1b: 'pass1b',
  pass2: 'pass2',
  pass3: 'pass3',
  pass4: 'pass4',
  pass5: 'pass5',
}

test.describe('basic', () => {

  let blindnet: typeof Blindnet
  let page: Page

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    page = await context.newPage()

    await page.goto(`file:${path.join(__dirname, 'index.html')}`)
  })

  test('browser supported', async () => {

    const res = await page.evaluate(async () => {
      const { Blindnet } = blindnet

      // @ts-ignore
      return await Blindnet.testBrowser()
    })

    expect(res).toBe(true)
  })

  test('deriving secret', async () => {

    const res = await page.evaluate(async data => {
      const { Blindnet } = blindnet

      // @ts-ignore
      let { blindnetSecret } = await Blindnet.deriveSecrets(data.pass1a)

      return ({ blindnetSecret })
    }, data)

    expect(res).toEqual({
      blindnetSecret: "+ub6EWRFGz4znKzZRx3ssicgfbhLZ9Xj8e4MTLiaffg=",
    })
  })
})

test.describe('connect', async () => {

  let blindnet: typeof Blindnet
  let page: Page
  let secret: string

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    page = await context.newPage()

    await page.goto(`file:${path.join(__dirname, 'index.html')}`)

    secret = await page.evaluate(async data =>
      blindnet.Blindnet.deriveSecrets(data.pass1a).then(s => s.blindnetSecret),
      data
    )
  })

  test('fail with 401 for bad token', async () => {

    const res = await page.evaluate(async ({ data, secret }) => {

      const bn = blindnet.Blindnet.init('', data.endpoint)

      return bn.connect(secret).catch(e => e.code)
    }, { data, secret })

    expect(res).toBe('blindnet.authentication')
  })

  test('successfully register a new user', async () => {
    await page.evaluate(async ({ data, secret }) => {
      // @ts-ignore
      const token = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      const bn = blindnet.Blindnet.init(token, data.endpoint)

      await bn.connect(secret)
    }, { data, secret })
  })

  test('connect an existing user', async () => {
    await page.evaluate(async ({ data, secret }) => {
      // @ts-ignore
      const token = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      const bn = blindnet.Blindnet.init(token, data.endpoint)

      await bn.connect(secret)
    }, { data, secret })
  })
})

test.describe('encryption', async () => {

  let blindnet: typeof Blindnet
  let page: Page
  let secrets: { secret1: string, secret2: string, secret3: string, secret4: string }

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    page = await context.newPage()

    await page.goto(`file:${path.join(__dirname, 'index.html')}`)

    const secret1 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass1a).then(s => s.blindnetSecret), data)
    const secret2 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass2).then(s => s.blindnetSecret), data)
    const secret3 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass3).then(s => s.blindnetSecret), data)
    const secret4 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass4).then(s => s.blindnetSecret), data)

    secrets = { secret1, secret2, secret3, secret4 }
  })

  test('user encrypts for self', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // @ts-ignore
      const token = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      const bn = blindnet.Blindnet.init(token, data.endpoint)
      await bn.connect(secrets.secret1)

      const enc1 = await bn.capture('test string').forUser(data.user1).encrypt()
      const enc2 = await bn.capture({ test: 'json', x: 1 }).forUser(data.user1).encrypt()
      const enc3 = await bn.capture(new File(['content'], 'filename')).withMetadata({ meta: true }).forUser(data.user1).encrypt()

      const decrypted1 = await bn.decrypt(enc1.encryptedData)
      const decrypted2 = await bn.decrypt(enc2.encryptedData)
      const decrypted3 = await bn.decrypt(enc3.encryptedData)

      await bn.disconnect()

      return {
        decryptedString: decrypted1,
        decryptedObject: decrypted2,
        decryptedFile: {
          // @ts-ignore
          data: decrypted3.data.name,
          metadata: decrypted3.metadata,
          dataType: decrypted3.dataType
        }
      }

    }, { data, secrets })

    expect(res).toEqual({
      decryptedString: { data: 'test string', metadata: {}, dataType: { type: 'String' } },
      decryptedObject: {
        data: { test: 'json', x: 1 },
        metadata: {},
        dataType: { type: 'Json' }
      },
      decryptedFile: {
        data: 'filename',
        metadata: { meta: true },
        dataType: { type: 'File', name: 'filename' }
      }
    })
  })

  test('user encrypts for other users', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // @ts-ignore
      const token1 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      let bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.disconnect()

      // @ts-ignore
      const token2 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user2).inGroup(data.group1).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      await bn.disconnect()

      // @ts-ignore
      const token3 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user3).inGroup(data.group2).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token3, data.endpoint)
      await bn.connect(secrets.secret3)

      const enc = await bn.capture('test').withMetadata({ x: 1 }).forUsers([data.user1, data.user2]).encrypt()

      bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      const decrypted1 = await bn.decrypt(enc.encryptedData)
      await bn.disconnect()

      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      const decrypted2 = await bn.decrypt(enc.encryptedData)
      await bn.disconnect()

      return {
        decrypted1,
        decrypted2
      }
    }, { data, secrets })

    expect(res).toEqual({
      decrypted1: {
        data: 'test',
        metadata: { x: 1 },
        dataType: { type: 'String' }
      },
      decrypted2: {
        data: 'test',
        metadata: { x: 1 },
        dataType: { type: 'String' }
      }
    }
    )
  })

  test('unregistered user encrypts for other users in a group', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // @ts-ignore
      const token1 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      let bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.disconnect()

      // @ts-ignore
      const token2 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user2).inGroup(data.group1).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      await bn.disconnect()

      // @ts-ignore
      const token3 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user3).inGroup(data.group2).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token3, data.endpoint)
      await bn.connect(secrets.secret3)
      await bn.disconnect()

      // @ts-ignore
      const unregToken = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).toCaptureData.forGroup(data.group1).lifetime(3600).build()

      bn = blindnet.Blindnet.init(unregToken, data.endpoint)
      const enc1 = await bn.capture('test 1').withMetadata({ x: 1 }).forUser(data.user1).encrypt()
      const enc2 = await bn.capture('test 2').withMetadata({ x: 2 }).forUsers([data.user1, data.user2]).encrypt()
      const enc3 = await bn.capture('test 3').withMetadata({ x: 3 }).forGroup(data.group1).encrypt()
      const error = await bn.capture('').forUsers([data.user1, data.user2, data.user3]).encrypt().catch(e => e.code)
      await bn.disconnect()

      bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      const decrypted1a = await bn.decrypt(enc1.encryptedData)
      const decrypted2a = await bn.decrypt(enc2.encryptedData)
      const decrypted3a = await bn.decrypt(enc3.encryptedData)
      await bn.disconnect()

      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      const [decrypted2b, decrypted3b] = await bn.decryptMany([enc2.encryptedData, enc3.encryptedData])
      await bn.disconnect()

      return {
        decrypted1a,
        decrypted2a,
        decrypted3a,
        decrypted2b,
        decrypted3b,
        error
      }
    }, { data, secrets })

    expect(res).toEqual({
      decrypted1a: { data: 'test 1', metadata: { x: 1 }, dataType: { type: 'String' }},
      decrypted2a: { data: 'test 2', metadata: { x: 2 }, dataType: { type: 'String' }},
      decrypted3a: { data: 'test 3', metadata: { x: 3 }, dataType: { type: 'String' }},
      decrypted2b: { data: 'test 2', metadata: { x: 2 }, dataType: { type: 'String' }},
      decrypted3b: { data: 'test 3', metadata: { x: 3 }, dataType: { type: 'String' }},
      error: 'blindnet.authentication'
    })
  })

  test('unregistered user encrypts for other specified users', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // @ts-ignore
      const token1 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      let bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.disconnect()

      // @ts-ignore
      const token2 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user2).inGroup(data.group1).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      await bn.disconnect()

      // @ts-ignore
      const token3 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user3).inGroup(data.group2).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token3, data.endpoint)
      await bn.connect(secrets.secret3)
      await bn.disconnect()

      // @ts-ignore
      const unregToken = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).toCaptureData.forUsers([data.user1, data.user3]).lifetime(3600).build()

      bn = blindnet.Blindnet.init(unregToken, data.endpoint)
      const enc1 = await bn.capture('test 1').forUser(data.user1).encrypt()
      const enc2 = await bn.capture('test 2').forUser(data.user3).encrypt()
      const enc3 = await bn.capture('test 3').forUsers([data.user1, data.user3]).encrypt()
      const error = await bn.capture('').forUser(data.user2).encrypt().catch(e => e.code)
      await bn.disconnect()

      bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      const [decrypted1a, decrypted3a] = await bn.decryptMany([enc1.encryptedData, enc3.encryptedData])
      await bn.disconnect()

      bn = blindnet.Blindnet.init(token3, data.endpoint)
      await bn.connect(secrets.secret3)
      const [decrypted2b, decrypted3b] = await bn.decryptMany([enc2.encryptedData, enc3.encryptedData])
      await bn.disconnect()

      return {
        decrypted1a,
        decrypted3a,
        decrypted2b,
        decrypted3b,
        error
      }
    }, { data, secrets })

    expect(res).toEqual({
      decrypted1a: { data: 'test 1', metadata: {}, dataType: { type: 'String' }},
      decrypted3a: { data: 'test 3', metadata: {}, dataType: { type: 'String' }},
      decrypted2b: { data: 'test 2', metadata: {}, dataType: { type: 'String' }},
      decrypted3b: { data: 'test 3', metadata: {}, dataType: { type: 'String' }},
      error: 'blindnet.authentication'
    })
  })

})

test.describe('giving access', async () => {

  let blindnet: typeof Blindnet
  let page: Page
  let secrets: { secret1: string, secret2: string }

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    page = await context.newPage()

    await page.goto(`file:${path.join(__dirname, 'index.html')}`)

    const secret1 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass1a).then(s => s.blindnetSecret), data)
    const secret2 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass2).then(s => s.blindnetSecret), data)

    secrets = { secret1, secret2 }
  })

  test('user gives access to specified data', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // connect user 1
      // @ts-ignore
      const token1 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      let bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.disconnect()

      // connect user 2 and encrypt for user 1
      // @ts-ignore
      const token2 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user2).inGroup(data.group2).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      const enc1 = await bn.capture('test 1').forUser(data.user1).encrypt()
      const enc2 = await bn.capture('test 2').forUser(data.user1).encrypt()
      await bn.disconnect()

      // connect user 1 and give access to previously encrypted data to user 2
      bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.giveAccessToData([enc1.dataId, enc2.dataId], data.user2)
      await bn.disconnect()

      // connect user 2 and decrypt data
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      const decrypted1 = await bn.decrypt(enc1.encryptedData)
      const decrypted2 = await bn.decrypt(enc2.encryptedData)

      return {
        dec1: decrypted1.data,
        dec2: decrypted2.data,
      }

    }, { data, secrets })

    expect(res).toEqual({
      dec1: 'test 1', dec2: 'test 2'
    })
  })

  test('user gives access to all data', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // connect user 1
      // @ts-ignore
      const token1 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      let bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.disconnect()

      // connect user 2 and encrypt for user 1
      // @ts-ignore
      const token2 = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user2).inGroup(data.group2).lifetime(3600).build()
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      const enc1 = await bn.capture('test 1').forUser(data.user1).encrypt()
      const enc2 = await bn.capture('test 2').forUser(data.user1).encrypt()
      await bn.disconnect()

      // connect user 1 and give access to all data to user 2
      bn = blindnet.Blindnet.init(token1, data.endpoint)
      await bn.connect(secrets.secret1)
      await bn.giveAccessToAllData(data.user2)
      await bn.disconnect()

      // connect user 2 and decrypt data
      bn = blindnet.Blindnet.init(token2, data.endpoint)
      await bn.connect(secrets.secret2)
      const decrypted1 = await bn.decrypt(enc1.encryptedData)
      const decrypted2 = await bn.decrypt(enc2.encryptedData)

      return {
        dec1: decrypted1.data,
        dec2: decrypted2.data,
      }

    }, { data, secrets })

    expect(res).toEqual({
      dec1: 'test 1', dec2: 'test 2'
    })
  })
})

test.describe('changing secret', async () => {
  let blindnet: typeof Blindnet
  let page: Page
  let secrets: { secret: string, newSecret: string }

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    page = await context.newPage()

    await page.goto(`file:${path.join(__dirname, 'index.html')}`)

    const secret = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass1a).then(s => s.blindnetSecret), data)
    const newSecret = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass1b).then(s => s.blindnetSecret), data)

    secrets = { secret, newSecret }
  })

  test('user changess secret and keep access to data', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // @ts-ignore
      const token = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      const bn = blindnet.Blindnet.init(token, data.endpoint)
      await bn.connect(secrets.secret)

      const enc1 = await bn.capture('test 1').forUser(data.user1).encrypt()

      await bn.changeSecret(secrets.newSecret)

      const enc2 = await bn.capture('test 2').forUser(data.user1).encrypt()
      const decrypted1 = await bn.decrypt(enc1.encryptedData)

      await bn.disconnect()
      bn.refreshToken(token)
      await bn.connect(secrets.newSecret)
      const decrypted2 = await bn.decrypt(enc1.encryptedData)
      const decrypted3 = await bn.decrypt(enc2.encryptedData)

      await bn.changeSecret(secrets.secret)
      const decrypted4 = await bn.decrypt(enc1.encryptedData)
      const decrypted5 = await bn.decrypt(enc2.encryptedData)

      return {
        dec1: decrypted1.data,
        dec2: decrypted2.data,
        dec3: decrypted3.data,
        dec4: decrypted4.data,
        dec5: decrypted5.data
      }

    }, { data, secrets })

    expect(res).toEqual({
      dec1: 'test 1', dec2: 'test 1', dec3: 'test 2', dec4: 'test 1', dec5: 'test 2'
    })
  })
})

test.describe('storage', async () => {

  let blindnet: typeof Blindnet
  let page: Page
  let secrets: { secret1: string, secret2: string }

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    page = await context.newPage()

    await page.goto(`file:${path.join(__dirname, 'index.html')}`)

    const secret1 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass1a).then(s => s.blindnetSecret), data)
    const secret2 = await page.evaluate(async data => blindnet.Blindnet.deriveSecrets(data.pass2).then(s => s.blindnetSecret), data)

    secrets = { secret1, secret2 }
  })

  test('file is stored and retrieved', async () => {
    const res = await page.evaluate(async ({ data, secrets }) => {
      // @ts-ignore
      const token = await blindnetTokenGenerator.TokenBuilder
        .init(data.key).forApp(data.appId).forUser.withId(data.user1).inGroup(data.group1).lifetime(3600).build()
      const bn = blindnet.Blindnet.init(token, data.endpoint)
      await bn.connect(secrets.secret1)

      const stored = await bn.capture(new File(['this is file content'], 'filename')).withMetadata({ x: 1 }).forUser(data.user1).store()

      const retrieved = await bn.retrieve(stored.dataId)
      
      const fileContent = await new Response(retrieved.data).arrayBuffer()

      return {
        fileContent: new TextDecoder().decode(fileContent),
        meta: retrieved.metadata
      }

    }, { data, secrets })

    expect(res).toEqual({
      fileContent: 'this is file content',
      meta: { x: 1 }
    })
  })
})