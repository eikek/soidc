package soidc.jwt

import java.nio.charset.StandardCharsets
import java.security.*
import java.security.spec.ECGenParameterSpec

import munit.FunSuite
import scodec.bits.*

class EcDerCodecTest extends FunSuite with Syntax:
  val sample = ByteVector.apply("hello world".getBytes(StandardCharsets.UTF_8))
  val javaDerSig =
    hex"30450220412e2ee26453abbdf43214439214705e624cb1c8ebf0df40ae2a5757f0b708a6022100c7619016e43891bd42887222d50b20f657172d5408591970742321a8a47577e0"

  val ecPrivateKey = EcKey.readEcPrivateKey(KeyData.ecPrivate).value
  val ecPublicKey = EcKey.readEcPubliceKey(KeyData.ecPublic).value

  def createCorrectDerSignature(
      payload: ByteVector,
      key: PrivateKey,
      alg: Algorithm
  ) =
    val signer = Signature.getInstance(alg.javaName)
    signer.initSign(key)
    signer.update(payload.toArray)
    ByteVector.apply(signer.sign())

  def generateKey(curve: Curve) =
    val spec = ECGenParameterSpec(curve.name)
    val kg = KeyPairGenerator.getInstance("EC")
    kg.initialize(spec, new java.security.SecureRandom)
    kg.generateKeyPair()

  def verifySignature(
      payload: ByteVector,
      derSignature: Array[Byte],
      key: PublicKey,
      alg: Algorithm
  ): Boolean =
    val signer = Signature.getInstance(alg.javaName)
    signer.initVerify(key)
    signer.update(payload.toArray)
    signer.verify(derSignature)

  test("encode and decode java generated der signature with static key"):
    val derSig = createCorrectDerSignature(sample, ecPrivateKey, Algorithm.Sign.ES256)
    assert(verifySignature(sample, derSig.toArray, ecPublicKey, Algorithm.Sign.ES256))
    val rsSig = EcDerCodec.derSignatureToRS(derSig, 64).value
    val backDer = EcDerCodec.rsSignatureToDER(rsSig).value
    assertEquals(backDer, derSig)

  test("encode/decode given der signature"):
    val rsSig = EcDerCodec.derSignatureToRS(javaDerSig, 64).value
    val backDer = EcDerCodec.rsSignatureToDER(rsSig).value
    assertEquals(backDer, javaDerSig)

  for {
    alg <- List(Algorithm.Sign.ES256, Algorithm.Sign.ES384, Algorithm.Sign.ES512)
    crv <- Curve.values
  }
    test(s"encode and decode java generated der signature $alg $crv"):
      val kp = generateKey(crv)
      val derSig = createCorrectDerSignature(sample, kp.getPrivate(), alg)
      assert(verifySignature(sample, derSig.toArray, kp.getPublic(), alg))
      val rsSig = EcDerCodec.derSignatureToRS(derSig, crv.expectedSignatureLength).value
      val backDer = EcDerCodec.rsSignatureToDER(rsSig).value
      assertEquals(backDer, derSig, s"${backDer.toHex} != ${derSig.toHex}")

  extension (alg: Algorithm)
    def javaName: String = alg match
      case Algorithm.Sign.ES256 => "SHA256withECDSA"
      case Algorithm.Sign.ES384 => "SHA384withECDSA"
      case Algorithm.Sign.ES512 => "SHA512withECDSA"
      case _                    => throw JwtError.UnsupportedSignatureAlgorithm(alg)

  extension (self: Curve)
    def expectedSignatureLength = self match
      case Curve.P256 => 64
      case Curve.P384 => 96
      case Curve.P521 => 132
