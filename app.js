const express = require('express')
const app = express()
const fs = require('fs')
const http = require('http')
const crypto = require('crypto')
const bodyParser = require('body-parser')

const SERVER_PORT = 3001

const server = http.createServer(app)

app.get('/', (req, res) => {
  res.end(fs.readFileSync(__dirname + '/index.html'))
})

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.post('/check', (req, res) => {
  const getHmac512 = (data, secret) => {
    const hmac = crypto.createHmac('sha512', secret)
    hmac.update(data)
    return hmac.digest('hex')
  }
  const genSalt = () => {
    return crypto.randomBytes(64)
  }
  const hex2Buf = (hex) => {
    return Buffer.from(hex, 'hex')
  }
  const calcPBKDF2 = (data, salt) => {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(data, salt, 1000*1000, 64, 'sha512', (err, derivedKey) => {
        if(err) {
          return resolve(null)
        }
        return resolve(derivedKey.toString('hex'))
      })
    })
  }

  const main = async () => {
    const hmacSecret = req.body.hmacSecret
    const data = req.body.data
    const hmac = req.body.hmac
    const saltHex = req.body.saltHex
    const pbkdf2 = req.body.pbkdf2
    let result = ''

    console.log('data:', data)
    console.log('hmac:', hmac)
    console.log('saltHex:', saltHex)
    console.log('pbkdf2:', pbkdf2)
    console.log('---\n')

    const hmacCorrect = getHmac512(data, hmacSecret)
    console.log('HMAC:', hmac === hmacCorrect, hmacCorrect)
    result += 'HMAC is correct? [' + (hmac === hmacCorrect) + ']\n'

    const salt = hex2Buf(saltHex)
    //  const salt = genSalt()
    console.log('salt', salt)
    const pbkdf2Correct = await calcPBKDF2(data, salt)
    console.log('PBKDF2:', pbkdf2 === pbkdf2Correct, pbkdf2Correct)
    result += 'PBKDF2 is correct? [' + (pbkdf2 === pbkdf2Correct) + ']'
    console.log(result)
    res.end(result)
    console.log('---\n')
  }
  main()
})

server.listen(SERVER_PORT, () => {
  console.log('Web server start at port', SERVER_PORT)
})

