package soidc.jwt

import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import scodec.bits.ByteVector

private[jwt] object RsaOaep:
  private val rsaOaep = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
  private val rsaOaep1 = "RSA/ECB/OAEPWithSHA1AndMGF1Padding"

  def encryptCEK1(cek: SecretKey, pk: PublicKey): Either[JwtError, ByteVector] =
    encryptCEK(cek, pk, rsaOaep1)

  def decryptCEK1(data: Array[Byte], pk: PrivateKey): Either[JwtError, SecretKeySpec] =
    decryptCEK(data, pk, rsaOaep1)

  def encryptCEK256(cek: SecretKey, pk: PublicKey): Either[JwtError, ByteVector] =
    encryptCEK(cek, pk, rsaOaep)

  def decryptCEK256(data: Array[Byte], pk: PrivateKey): Either[JwtError, SecretKeySpec] =
    decryptCEK(data, pk, rsaOaep)

  private def encryptCEK(
      cek: SecretKey,
      pk: PublicKey,
      alg: String
  ): Either[JwtError, ByteVector] =
    wrapSecurityApi {
      val cipher = Cipher.getInstance(alg)
      cipher.init(Cipher.ENCRYPT_MODE, pk, new SecureRandom)
      ByteVector.view(cipher.doFinal(cek.getEncoded()))
    }

  private def decryptCEK(
      data: Array[Byte],
      pk: PrivateKey,
      alg: String
  ): Either[JwtError, SecretKeySpec] =
    wrapSecurityApi {
      val cipher = Cipher.getInstance(alg)
      cipher.init(Cipher.DECRYPT_MODE, pk)
      new SecretKeySpec(cipher.doFinal(data), "AES")
    }
