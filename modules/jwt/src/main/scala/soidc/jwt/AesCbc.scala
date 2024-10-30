package soidc.jwt

import scodec.bits.ByteVector
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.security.InvalidKeyException
import javax.crypto.Mac
import javax.crypto.KeyGenerator

/** See https://datatracker.ietf.org/doc/html/rfc7518#section-5.2 */
private[jwt] object AesCbc:

  val cipherId = "AES/CBC/PKCS5Padding"
  val ivLengthBits = 128

  def generateIV = {
    val sr = new SecureRandom
    val bytes = new Array[Byte](ivLengthBits / 8)
    sr.nextBytes(bytes)
    ByteVector.view(bytes)
  }

  def generateKey(len: 256 | 384 | 512) =
    CompositeKey.generate(len)

  def encryptOnly(
      secretKey: SecretKey,
      iv: ByteVector,
      clearText: ByteVector
  ) = {
    val cipher = Cipher.getInstance(cipherId)
    val keySpec = new SecretKeySpec(secretKey.getEncoded, "AES")
    val ivSpec = new IvParameterSpec(iv.toArray)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

    val out = cipher.doFinal(clearText.toArray)
    ByteVector.view(out)
  }

  def decryptOnly(
      secretKey: SecretKey,
      iv: ByteVector,
      cipherText: ByteVector
  ) = {
    val cipher = Cipher.getInstance(cipherId)
    val keySpec = new SecretKeySpec(secretKey.getEncoded, "AES")
    val ivSpec = new IvParameterSpec(iv.toArray)
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    val out = cipher.doFinal(cipherText.toArray)
    ByteVector.view(out)
  }

  def encryptAuthenticated(
      secretKey: SecretKey,
      iv: ByteVector,
      clearText: ByteVector,
      authData: ByteVector
  ) = wrapSecurityApi {
    val cck = CompositeKey.create(secretKey)
    val cipherText = encryptOnly(cck.encKey, iv, clearText)

    val hmac = doMac(cck.macKey, iv, cipherText, authData)
    val authTag = hmac.take(cck.truncatedIndex)

    AesGcm.Result(cipherText, authTag, iv)
  }

  private def doMac(
      macKey: SecretKey,
      iv: ByteVector,
      cipherText: ByteVector,
      authData: ByteVector
  ) = {
    val al = authData.bits.length
    val alBytes = BigInt(al).toByteArray
    val macData = authData ++ iv ++ cipherText ++ ByteVector.view(alBytes)

    val mac = Mac.getInstance(macKey.getAlgorithm())
    mac.init(macKey)
    mac.update(macData.toArray)
    ByteVector.view(mac.doFinal())
  }

  def decryptAuthenticated(
      secretKey: SecretKey,
      iv: ByteVector,
      cipherText: ByteVector,
      authData: ByteVector,
      authTag: ByteVector
  ) = wrapSecurityApi {
    val cck = CompositeKey.create(secretKey)

    val hmac = doMac(cck.macKey, iv, cipherText, authData)
    val expectAuthTag = hmac.take(cck.truncatedIndex)

    if (authTag.equalsConstantTime(expectAuthTag)) {
      decryptOnly(cck.encKey, iv, cipherText)
    } else {
      throw new Exception("MAC check failed!")
    }
  }

  final case class CompositeKey(
      raw: SecretKey,
      macKey: SecretKey,
      encKey: SecretKey,
      truncatedIndex: Int
  )
  object CompositeKey {
    def generate(len: 256 | 384 | 512) = {
      val kgen = KeyGenerator.getInstance("AES")
      kgen.init(len / 2)
      val macGen = KeyGenerator.getInstance(s"HMACSHA${len}")
      macGen.init(len / 2)
      val macKey = macGen.generateKey
      val aesKey = kgen.generateKey
      val raw =
        ByteVector.view(macKey.getEncoded()) ++ ByteVector.view(aesKey.getEncoded())
      CompositeKey(new SecretKeySpec(raw.toArray, "AES"), macKey, aesKey, len / 8 / 2)
    }

    def create(raw: SecretKey) = {
      val rawBytes = raw.getEncoded()
      rawBytes.length match
        case 32 =>
          CompositeKey(
            raw,
            new SecretKeySpec(rawBytes, 0, 16, "HMACSHA256"),
            new SecretKeySpec(rawBytes, 16, 16, "AES"),
            16
          )

        case 48 =>
          CompositeKey(
            raw,
            new SecretKeySpec(rawBytes, 0, 24, "HMACSHA384"),
            new SecretKeySpec(rawBytes, 24, 24, "AES"),
            24
          )

        case 64 =>
          CompositeKey(
            raw,
            new SecretKeySpec(rawBytes, 0, 32, "HMACSHA512"),
            new SecretKeySpec(rawBytes, 32, 32, "AES"),
            32
          )

        case _ =>
          throw new InvalidKeyException(
            s"Unuspported $cipherId HMAC key. Length must be 256,384 or 512 bits, but was ${rawBytes.length * 8}"
          )
    }
  }
