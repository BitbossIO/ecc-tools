DefaultAlgoritm = 'aes'
Algorithms =
  aes: 'aes-256-cbc'
  triple: 'triplesec'
  triplesec: 'triplesec'
  'aes-256-cbc': 'aes-256-cbc'

promise = Promise ? require('es6-promise').Promise

crypto = require 'crypto'
secp256k1 = require 'secp256k1'
bs58check = require 'bs58check'
triplesec = require 'triplesec'

stringify = require 'json-stable-stringify'

assert = (condition, message) ->
  if !condition then throw new Error(message || "Assertion failed")

equalConstTime = (b1, b2) ->
  return false if (b1.length != b2.length)
  res = 0
  res |= b1[i] ^ b2[i] for i in [0...b1.length]
  res == 0;

pad32 = (msg) ->
  if (msg.length < 32)
    buf = new Buffer(32)
    buf.fill(0)
    msg.copy(buf, 32 - msg.length)
    return buf
  else return msg

ecctoolkit =
  stringify: stringify
  bs58check: bs58check
  secp256k1: secp256k1

  sha256: (msg) -> crypto.createHash("sha256").update(msg).digest()
  sha512: (msg) -> crypto.createHash("sha512").update(msg).digest()

  hmacSha256: (key, msg) -> crypto.createHmac("sha256", key).update(msg).digest()

  checksum: (msg) -> @sha256(stringify(msg))

  privateKey: ->  crypto.randomBytes(32)
  publicKey: (privateKey, compressed=false) -> secp256k1.publicKeyCreate(privateKey, compressed)

  publicKeyConvert: (publicKey, compressed=false) -> secp256k1.publicKeyConvert(publicKey, compressed)

  derive: (privateKey, publicKey) -> secp256k1.ecdhUnsafe(publicKey, privateKey).slice(1,33)

  sign: (msg, privateKey) ->
    msg = msg.toBuffer?() ? msg
    privateKey = privateKey.toBuffer?() ? privateKey
    assert(msg.length > 0, "Message should not be empty")
    assert(msg.length <= 32, "Message is too long")
    sig = secp256k1.sign(pad32(msg), privateKey).signature
    secp256k1.signatureExport(sig)

  verify: (msg, publicKey, sig) ->
    msg = msg.toBuffer?() ? msg
    sig = sig.toBuffer?() ? sig
    publicKey = publicKey.toBuffer?() ? publicKey
    assert(msg.length > 0, "Message should not be empty")
    assert(msg.length <= 32, "Message is too long")
    sig = secp256k1.signatureImport(sig)
    secp256k1.verify(pad32(msg), sig, publicKey)

  encrypt: (plaintext, publicKey, algorithm=DefaultAlgoritm) ->
    promise.resolve(plaintext).then (plaintext) =>
      algorithm = Algorithms[algorithm] ? algorithm

      privateKey = crypto.randomBytes(32)
      ephemeralKey = @publicKey(privateKey, true)
      hash = @sha512(@derive(privateKey, publicKey))
      iv = crypto.randomBytes(16)
      encryptionKey = hash.slice(0, 32)
      macKey = hash.slice(32)

      @cipher(plaintext, encryptionKey, iv, algorithm).then (ciphertext) =>
        dataToMac = Buffer.concat([iv, ephemeralKey, ciphertext])
        mac = @hmacSha256(macKey, dataToMac)

        iv: iv
        mac: mac
        ciphertext: ciphertext
        ephemeralKey: ephemeralKey

  decrypt: (cipher, privateKey, algorithm=DefaultAlgoritm) ->
    promise.resolve(cipher).then (cipher) =>
      algorithm = Algorithms[algorithm] ? algorithm

      ciphertext = cipher.ciphertext.toBuffer?() ? cipher.ciphertext
      iv = cipher.iv.toBuffer?() ? cipher.iv
      mac = cipher.mac.toBuffer?() ? cipher.mac
      ephemPublicKey = cipher.ephemeralKey.toBuffer?() ? cipher.ephemeralKey

      hash = @sha512(@derive(privateKey, ephemPublicKey))
      encryptionKey = hash.slice(0, 32)
      macKey = hash.slice(32)
      dataToMac = Buffer.concat([
        iv,
        ephemPublicKey,
        ciphertext
      ])
      realMac = @hmacSha256(macKey, dataToMac)
      assert(equalConstTime(mac, realMac), 'Bad MAC')
      @decipher(ciphertext, encryptionKey, iv, algorithm)

  cipher: (plaintext, key, iv, algorithm=DefaultAlgoritm) ->
    promise.resolve(plaintext).then (plaintext) ->
      algorithm = Algorithms[iv] ? Algorithms[algorithm] ? algorithm
      plaintext = stringify(plaintext)

      switch algorithm
        when 'triplesec'
          new promise (resolve, reject) ->
            triplesec.encrypt { data: new Buffer(plaintext), key: key }, (err, ciphertext) ->
              if err? then reject(new Error(err))
              else resolve(ciphertext)
        else
          cipher = crypto.createCipheriv(algorithm, key, iv)
          firstChunk = cipher.update(plaintext)
          secondChunk = cipher.final()
          Buffer.concat([firstChunk, secondChunk])
    .then (ciphertext) -> new Buffer(ciphertext)

  decipher: (ciphertext, key, iv, algorithm=DefaultAlgoritm) ->
    promise.resolve(ciphertext).then (ciphertext) ->
      algorithm = Algorithms[iv] ? Algorithms[algorithm]

      switch algorithm
        when 'triplesec'
          new promise (resolve, reject) ->
            triplesec.decrypt { data: ciphertext, key: key }, (err, ciphertext) ->
              if err? then reject(new Error(err))
              else resolve(ciphertext)
        else
          cipher = crypto.createDecipheriv(algorithm, key, iv)
          firstChunk = cipher.update(ciphertext)
          secondChunk = cipher.final()
          Buffer.concat([firstChunk, secondChunk])

    .then (plaintext) -> JSON.parse(plaintext)


module.exports = ecctoolkit
