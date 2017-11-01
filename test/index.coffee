chai = require 'chai'
expect = chai.expect

ecc = require '../src'

describe 'ECC Tools', ->
  before ->
    @alicePrivateKey = new Buffer('092cea22832ff99ad1d0bad976c7d354fbc938e0ba59711d7a66694c75291106', 'hex')
    @alicePublicKey = new Buffer('03b471796adff784450ef8ed3018256bced96b8a770117fd7c6ce2fb6cf476b120', 'hex')
    @alicePublicKeyUncompressed = new Buffer('04b471796adff784450ef8ed3018256bced96b8a770117fd7c6ce2fb6cf476b120db07652cb9a5b789e01df7fc1bbab98fa3d0880b1643df18742e5219d1684cb5', 'hex')

    @bobPrivateKey = ecc.sha256('secret bob')
    @bobPublicKey = ecc.publicKey(@bobPrivateKey)

  describe 'Hashing', ->
    describe 'sha256', ->
      it 'should return a sha256 hash of a string', ->
        result = ecc.sha256('hello world').toString('hex')
        expect(result).to.equal('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')

    describe 'sha512', ->
      it 'should return a sha512 hash of a string', ->
        result = ecc.sha512('hello world').toString('hex')
        expect(result).to.equal('309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f')

    describe 'hmacSha256', ->
      it 'should return the sha256 hmac for a string and key', ->
        result = ecc.hmacSha256('fubar', 'hello world').toString('hex')
        expect(result).to.equal('8447e74f07e107d00658083e0a8ed3c7c4893db09c6577ffac7ed133d13ed834')

    describe 'checksum', ->
      it 'should return the sha256 hash of a javascript object stringified', ->
        result = ecc.checksum(a: 0, b: 1).toString('hex')
        expect(result).to.equal('f4c1d8bd90d7ccd720aa5a69a67185fb9caf4f35926a4eacf53a86d0e70bdf88')

  describe 'Encoding/Decoding', ->
    describe 'isHex', ->
      it 'should return true if string is hex', ->
        result = ecc.isHex('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')
        expect(result).to.be.true

      it 'should return false if string is not hex', ->
        result = ecc.isHex('1Yu2BuptuZSiBWfr2Qy4aic6qEVnwPWrdkHPEc')
        expect(result).to.be.false

    describe 'isBase58', ->
      it 'should return true if string is Base58', ->
        result = ecc.isBase58('1Yu2BuptuZSiBWfr2Qy4aic6qEVnwPWrdkHPEc')
        expect(result).to.be.true

      it 'should return false if string is not Base58', ->
        result = ecc.isBase58('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')
        expect(result).to.be.false

    describe 'decode', ->
      it 'should return a buffer if passed a buffer', ->
        result = ecc.decode(@alicePublicKey)
        expect(result).to.be.an.instanceof(Buffer)

      it 'should return a buffer if passed a Base58 encoded string', ->
        result = ecc.decode('5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr')
        expect(result).to.be.an.instanceof(Buffer)

      it 'should return a buffer if passed a hex encoded string', ->
        result = ecc.decode('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')
        expect(result).to.be.an.instanceof(Buffer)

      it 'should return a buffer if passed a hex encoded string that looks like a base58 encoded string', ->
        result = ecc.decode('ffffffffffffffff')
        expect(result).to.be.an.instanceof(Buffer)
        expect(result).to.eql(new Buffer('ffffffffffffffff', 'hex'))

  describe 'Keys', ->
    describe 'privateKey', ->
      it 'should generate a random 32byte private key', ->
        result = ecc.privateKey()
        expect(result).to.have.length(32)

    describe 'publicKey', ->
      it 'should return the uncompressed public key for a given private key by default', ->
        result = ecc.publicKey(@alicePrivateKey)
        expect(result).to.deep.equal(@alicePublicKeyUncompressed)

      it 'should return the compressed public key for a given private key if compress is set to true', ->
        result = ecc.publicKey(@alicePrivateKey, true)
        expect(result).to.deep.equal(@alicePublicKey)

    describe 'publicKeyConvert', ->
      it 'should return the uncompressed public key for a compressed public key', ->
        result = ecc.publicKeyConvert(@alicePublicKey)
        expect(result).to.deep.equal(@alicePublicKeyUncompressed)

      it 'should return the compressed public key for a uncompressed public key', ->
        result = ecc.publicKeyConvert(@alicePublicKeyUncompressed, true)
        expect(result).to.deep.equal(@alicePublicKey)

      it 'should return the compressed public key for a compressed public key', ->
        result = ecc.publicKeyConvert(@alicePublicKey, true)
        expect(result).to.deep.equal(@alicePublicKey)

    describe 'derive', ->
      it 'should derive shared secret from a private key and a public key', ->
        aliceShared = ecc.derive(@alicePrivateKey, @bobPublicKey)
        bobShared = ecc.derive(@bobPrivateKey, @alicePublicKey)
        expect(aliceShared).to.deep.equal(bobShared)

  describe 'ECDSA', ->
    describe 'sign', ->
      it 'should sign a message with a private key', ->
        signature = ecc.sign(ecc.sha256('secret message'), @alicePrivateKey)
        result = ecc.verify(ecc.sha256('secret message'), @alicePublicKey, signature )
        expect(result).to.be.true

      it 'should error if message is empty', ->
        signing = => ecc.sign('', @alicePrivateKey)
        expect(signing).to.throw(Error, /Message should not be empty/)

      it 'should error if message is over 32bytes', ->
        signing = => ecc.sign(Buffer(33), @alicePrivateKey)
        expect(signing).to.throw(Error, /Message is too long/)

    describe 'verify', ->
      it 'should verify a valid signature', ->
        signature = ecc.sign(ecc.sha256('secret message'), @alicePrivateKey)
        result = ecc.verify(ecc.sha256('secret message'), @alicePublicKey, signature )
        expect(result).to.be.true

      it 'should reject an invalid signature', ->
        signature = ecc.sign(ecc.sha256('secret message'), @alicePrivateKey)
        result = ecc.verify(ecc.sha256('secret messag'), @alicePublicKey, signature )
        expect(result).to.be.false

  describe 'ECIES', ->
    describe 'encrypt / decrypt', ->
      it 'should encrypt a message with a public key and decrypt with the private key',  ->
        ecc.encrypt('hello world', @alicePublicKey).then (cipher) =>
          ecc.decrypt(cipher, @alicePrivateKey).then (plaintext) ->
            expect(plaintext).to.equal('hello world')
