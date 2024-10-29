package soidc.jwt

import java.security.SecureRandom
import scodec.bits.ByteVector
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.KeyGenerator

private[jwt] object AesGcm:
  final case class Result(cipherText: ByteVector, authTag: ByteVector, iv: ByteVector)

  val ivLengthBits = 96
  val authTagBits = 128

  def generateIV = {
    val sr = new SecureRandom
    val bytes = new Array[Byte](ivLengthBits / 8)
    sr.nextBytes(bytes)
    ByteVector.view(bytes)
  }

  def generateKey(len: 128 | 192 | 256) = {
    val kgen = KeyGenerator.getInstance("AES")
    kgen.init(len)
    kgen.generateKey()
  }

  def encrypt(
      secretKey: SecretKey,
      iv: ByteVector,
      clearText: ByteVector,
      authData: ByteVector
  ) = wrapSecurityApi {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val gcmSpec = new GCMParameterSpec(authTagBits, iv.toArray)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    cipher.updateAAD(authData.toArray)

    val out = cipher.doFinal(clearText.toArray)
    val tagPos = out.length - (authTagBits / 8)

    val cipherText = ByteVector.view(out, 0, tagPos)
    val authTag = ByteVector.view(out, tagPos, authTagBits / 8)
    val usedIV = getUsedIV(cipher)
    Result(cipherText, authTag, usedIV)
  }

  private def getUsedIV(cipher: Cipher) = {
    val spec = Option(cipher.getParameters())
      .flatMap(e => Option(e.getParameterSpec(classOf[GCMParameterSpec])))
      .getOrElse(throw new Exception(s"AES GCM parameters could not be retrieved"))

    val iv = Option(spec.getIV()).map(ByteVector.view).getOrElse(ByteVector.empty)
    val tlen = spec.getTLen()
    if (iv.size != (ivLengthBits / 8))
      throw new Exception(
        s"Required iv length is $ivLengthBits bits, but got ${iv.size * 8}"
      )
    if (tlen != authTagBits)
      throw new Exception(s"Required authTag length is $authTagBits, but got $tlen")
    iv
  }

  def decrypt(
      secretKey: SecretKey,
      iv: ByteVector,
      cipherText: ByteVector,
      authData: ByteVector,
      authTag: ByteVector
  ) = wrapSecurityApi {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val gcmSpec = new GCMParameterSpec(authTagBits, iv.toArray)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
    cipher.updateAAD(authData.toArray)

    val out = cipher.doFinal((cipherText ++ authTag).toArray)
    ByteVector.view(out)
  }
