package soidc.jwt

import scodec.bits.ByteVector
import javax.crypto.Mac
import javax.crypto.SecretKey
import java.security.Signature

private object Sign:

  def signWith(payload: Array[Byte], key: JWK): Either[OidcError, ByteVector] =
    key.keyType match
      case KeyType.OCT =>
        for
          secret <- key.getSymmetricHmacKey
          mac <- getMac(secret)
          _ <- wrapSecurityApi(mac.update(payload))
          s = ByteVector.view(mac.doFinal())
        yield s

      case KeyType.EC =>
        signAsymmetric(key, payload, EcKey.signAlgoName)

      case KeyType.RSA =>
        signAsymmetric(key, payload, RsaKey.signAlgoName)

      case KeyType.OKP => Left(OidcError.UnsupportedPrivateKey(key.keyType))

  private def getMac(secret: SecretKey): Either[OidcError, Mac] =
    wrapSecurityApi {
      val m = Mac.getInstance(secret.getAlgorithm())
      m.init(secret)
      m
    }

  private def signAsymmetric(
      key: JWK,
      payload: Array[Byte],
      algoName: Algorithm => Either[OidcError, String]
  ) =
    for
      alg <- key.algorithm.toRight(OidcError.DecodeError("No algorithm in JWK"))
      algName <- algoName(alg)
      ppk <- key.getPrivateKey
      signature <- wrapSecurityApi(Signature.getInstance(algName))
      _ <- wrapSecurityApi {
        signature.initSign(ppk)
        signature.update(payload)
      }
      xs <-
        if (alg.isEC) ecExpectedSignatureLength(alg).flatMap { len =>
          derSignatureToRS(ByteVector.view(signature.sign), len)
          // wrapSecurityApi(transcodeSignatureToConcat(signature.sign, len))
        }
        else wrapSecurityApi(ByteVector.view(signature.sign))
//      s = ByteVector.view(xs)
    yield xs

  // TODO https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature
  // https://en.wikipedia.org/wiki/Two%27s_complement
  // https://superuser.com/questions/1023167/can-i-extract-r-and-s-from-an-ecdsa-signature-in-bit-form-and-vica-versa

  def derSignatureToRS(der: ByteVector, outLen: Int): Either[OidcError, ByteVector] =
    (for
      (rem0, _) <- der.consume(1)(bv =>
        Either.cond(bv.head == 0x30, (), s"Invalid DER signature: header byte: $bv")
      )
      offset = if (rem0.head > 0) 2 else 3
      (rem1, rLen) <- rem0.consume(offset + 1)(bv => Right(bv.last.toLong))
      (rem2, r) <- rem1.consume(rLen)(bv =>
        Right(bv.dropWhile(_ == 0).padLeft(outLen / 2))
      )
      (rem3, sLen) <- rem2.consume(2)(bv => Right(bv.last.toLong))
      (rem4, s) <- rem3.consume(sLen)(bv =>
        Right(bv.dropWhile(_ == 0).padLeft(outLen / 2))
      )
      _ <- Either.cond(rem4.isEmpty, (), "Invalid DER signature")
    yield r ++ s).left.map(OidcError.DecodeError(_))

  /** Transcodes the JCA ASN.1/DER-encoded signature into the concatenated R + S format
    * expected by ECDSA JWS.
    *
    * @param derSignature
    *   The ASN1./DER-encoded. Must not be {@code null} .
    * @param outputLength
    *   The expected length of the ECDSA JWS signature.
    * @return
    *   The ECDSA JWS encoded signature.
    * @throws JwtSignatureFormatException
    *   If the ASN.1/DER signature format is invalid.
    */
  @annotation.nowarn()
  private def transcodeSignatureToConcat(
      derSignature: Array[Byte],
      outputLength: Int
  ): Array[Byte] = {
    if (derSignature.length < 8 || derSignature(0) != 48)
      throw new Exception("Invalid ECDSA signature format")

    val offset: Int = derSignature(1) match {
      case s if s > 0            => 2
      case s if s == 0x81.toByte => 3
      case _                     => throw new Exception("Invalid ECDSA signature format")
    }

    val rLength: Byte = derSignature(offset + 1)
    var i = rLength.toInt
    while ((i > 0) && (derSignature((offset + 2 + rLength) - i) == 0))
      i -= 1

    val sLength: Byte = derSignature(offset + 2 + rLength + 1)
    var j = sLength.toInt
    while ((j > 0) && (derSignature((offset + 2 + rLength + 2 + sLength) - j) == 0))
      j -= 1

    val rawLen: Int = Math.max(Math.max(i, j), outputLength / 2)

    if (
      (derSignature(offset - 1) & 0xff) != derSignature.length - offset
      || (derSignature(offset - 1) & 0xff) != 2 + rLength + 2 + sLength
      || derSignature(offset) != 2 || derSignature(offset + 2 + rLength) != 2
    )
      throw new Exception("Invalid ECDSA signature format")

    val concatSignature: Array[Byte] = new Array[Byte](2 * rawLen)
    System.arraycopy(
      derSignature,
      (offset + 2 + rLength) - i,
      concatSignature,
      rawLen - i,
      i
    )
    System.arraycopy(
      derSignature,
      (offset + 2 + rLength + 2 + sLength) - j,
      concatSignature,
      2 * rawLen - j,
      j
    )
    concatSignature
  }

  /** Transcodes the ECDSA JWS signature into ASN.1/DER format for use by the JCA
    * verifier.
    *
    * @param signature
    *   The JWS signature, consisting of the concatenated R and S values. Must not be
    *   {@code null} .
    * @return
    *   The ASN.1/DER encoded signature.
    * @throws JwtSignatureFormatException
    *   If the ECDSA JWS signature format is invalid.
    */
  @annotation.nowarn()
  private def transcodeSignatureToDER(signature: Array[Byte]): Array[Byte] = {
    var (r, s) = signature.splitAt(signature.length / 2)
    r = r.dropWhile(_ == 0)
    if (r.length > 0 && r(0) < 0)
      r +:= 0.toByte

    s = s.dropWhile(_ == 0)
    if (s.length > 0 && s(0) < 0)
      s +:= 0.toByte

    val signatureLength = 2 + r.length + 2 + s.length

    if (signatureLength > 255)
      throw new Exception("Invalid ECDSA signature format")

    val signatureDER = scala.collection.mutable.ListBuffer.empty[Byte]
    signatureDER += 48
    if (signatureLength >= 128)
      signatureDER += 0x81.toByte

    signatureDER += signatureLength.toByte
    signatureDER ++= (Seq(2.toByte, r.length.toByte) ++ r)
    signatureDER ++= (Seq(2.toByte, s.length.toByte) ++ s)

    signatureDER.toArray
  }

  private def ecExpectedSignatureLength(alg: Algorithm) = alg match
    case Algorithm.ES256 => Right(64)
    case Algorithm.ES384 => Right(96)
    case Algorithm.ES512 => Right(132)
    case _ => Left(OidcError.DecodeError(s"Invalid algorithm for EC signatures: $alg"))
