import { Blindnet } from './index'
import { str2ab } from './helper'

export async function asd(n: number) {
  if (n == 0) return
  else if (n % 2 == 0) await test(true)
  else await test(false)
  return asd(n - 1)
}

async function test(swap: boolean = false) {
  const jwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMCIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.4KCp00fun1Drhh0QeuDkn-GEIm3XNZVS8hZMGSFMEGU"
  const jwt2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMSIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.SWD8ihR-QJDcvBvBWjzrOKrGNTUd2ZSkIIlr2Il4WkA"
  const otjwt1 = ""
  let pass1a = 'pass1'
  let pass1b = 'fjsdlkjflkds'
  let pass2a = 'asd'
  let pass2b = 'fjsldjflkds'

  // if (swap) {
  //   let temp: string = undefined
  //   temp = pass1a
  //   pass1a = pass1b
  //   pass1b = temp
  // }

  console.log('STARTING')

  let { blindnetPassphrase: derived1a } = await Blindnet.derivePasswords(pass1a)
  let { blindnetPassphrase: derived2a } = await Blindnet.derivePasswords(pass2a)

  let blindnet = Blindnet.init(jwt1, 'http://localhost:9000')
  await blindnet.login(derived1a)
  console.log('initialized user 1')
  await blindnet.login(derived1a)
  console.log('loaded user 1')
  await blindnet.login(derived1a)
  console.log('loaded user 1 again')

  // blindnet = Blindnet.init(jwt2, 'http://localhost:9000')
  // await blindnet.login(pass2a)
  // console.log('initialized user 2')

  blindnet = Blindnet.init(otjwt1, 'http://localhost:9000')
  console.log('started unregistered user')

  const encData = await blindnet.encrypt(str2ab('sup bro?'), str2ab('{ "name": "asd" }'))
  console.log('encrypted', encData)

  blindnet = Blindnet.init(jwt1, 'http://localhost:9000')
  await blindnet.login(derived1a)
  console.log('user 1 loaded')
  const decData = await blindnet.decrypt(encData.dataId, encData.encryptedData)
  console.log("data:        ", String.fromCharCode.apply(null, new Uint16Array(decData.data)))
  console.log("metadata:    ", JSON.parse(String.fromCharCode.apply(null, new Uint16Array(decData.metadata))))

  blindnet = Blindnet.init(jwt2, 'http://localhost:9000')
  await blindnet.login(derived2a)
  console.log('initialized user 2')

  blindnet = Blindnet.init(jwt1, 'http://localhost:9000')
  await blindnet.login(derived1a)
  console.log('user 1 loaded')

  await blindnet.giveAccess('user1')
  console.log('gave access to user 2')

  blindnet = Blindnet.init(jwt2, 'http://localhost:9000')
  await blindnet.login(derived2a)
  console.log('user 2 loaded')
  const decData2 = await blindnet.decrypt(encData.dataId, encData.encryptedData)
  console.log("data:        ", String.fromCharCode.apply(null, new Uint16Array(decData.data)))
  console.log("metadata:    ", JSON.parse(String.fromCharCode.apply(null, new Uint16Array(decData.metadata))))

  // await blindnet.updatePassphrase(pass1b)
  // console.log('user 1 pass updated')

  console.log('\n\n')
}