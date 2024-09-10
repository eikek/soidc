package soidc.jwt

import munit.*
import scodec.bits.{ByteVector, hex}
import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.JsonDecoder

class JWSTest extends FunSuite:

  test("split token"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val parts = JWS.unsafeFromString(token)
    assertEquals(parts.header.decodedUtf8.noWhitespace, """{"typ":"JWT","alg":"HS256"}""")
    assertEquals(
      parts.claims.decodedUtf8.noWhitespace,
      """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    )
    assertEquals(
      parts.signature.get.decoded,
      hex"7418dfb49799e0254ffa607dd8adbbba16d4254d69d6bff05b58055853848d79"
    )

  test("split token, no signature"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    val parts = JWS.unsafeFromString(token)
    assertEquals(parts.header.decodedUtf8.noWhitespace, """{"typ":"JWT","alg":"HS256"}""")
    assertEquals(
      parts.claims.decodedUtf8.noWhitespace,
      """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    )

  test("fail when no base64"):
    val token = "1.2.3"
    assert(JWS.fromString(token).isLeft)

  test("fail if no dot"):
    assert(JWS.fromString("uiaeuaieu").isLeft)

  test("decode value"):
    val header = JoseHeader.empty.withAlgorithm(Algorithm.HS256)
    given JsonDecoder[JoseHeader] = JsonDecoder.instance(bv =>
      Either.cond(
        bv == ByteVector.fromValidBase64("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"),
        header,
        DecodeError("wrong")
      )
    )
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    val parts = JWS.unsafeFromString(token)
    val result = parts.header.as[JoseHeader].fold(throw _, identity)
    assertEquals(result, header)

  test("JWS with HMAC signature"):
    val data = Rfc7515.Appendix1
    val jws = JWS(data.header64, data.claim64).unsafeSignWith(data.symmetricKey)
    assertEquals(jws.signature, Some(data.signature))

  test("JWS with RSA signature"):
    val data = Rfc7515.Appendix2
    val jws = JWS(data.header64, data.claim64).unsafeSignWith(data.rsaKey)
    assertEquals(jws.signature, Some(data.signature))

  test("JWS with EC signature"):
    val data = Rfc7515.Appendix3
    val jws = JWS(data.heade64, data.claim64).unsafeSignWith(data.ecKey)
    assertEquals(jws.signature, Some(data.signature))




    // https://github.com/felx/nimbus-jose-jwt/blob/master/src/main/java/com/nimbusds/jose/jwk/ECKey.java#L1125

    // val jws = JWS(
    //   Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"),
    //   Base64String.unsafeOf(
    //     "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    //   ),
    //   None
    // )
    // // openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -inform pem -nocrypt -topk8 > /tmp/ec.private.pem
    // // openssl ec -in /tmp/ec.private.pem -pubout -out /tmp/ec.public.pem
    // val ecPrivate = """-----BEGIN PRIVATE KEY-----
    //     |MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8kqABXEiSKJrc48y
    //     |ljklhnT+2TDc8W43iC5MS27WaCShRANCAARorbyspEAgTEJlnhQCWT2w7yupFC9r
    //     |ha176BXrQyuWNKvGOURmSuIfDLqRQj/n6hP2ZGzStq4RnUb9Nqwq6fWl
    //     |-----END PRIVATE KEY-----""".stripMargin

    // val ecPublic = """-----BEGIN PUBLIC KEY-----
    //     |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaK28rKRAIExCZZ4UAlk9sO8rqRQv
    //     |a4Wte+gV60MrljSrxjlEZkriHwy6kUI/5+oT9mRs0rauEZ1G/TasKun1pQ==
    //     |-----END PUBLIC KEY-----""".stripMargin

    // // val kf = KeyFactory.getInstance("EC")
    // // val encspec = PKCS8EncodedKeySpec(ByteVector.fromValidBase64(ecPrivatePlain).toArray)
    // // val ppk = kf.generatePrivate(encspec).asInstanceOf[ECPrivateKey]
    // // val params = AlgorithmParameters.getInstance("EC")
    // // params.init(ppk.getParams())
    // // println(params.getParameterSpec(classOf[ECGenParameterSpec]).getName())

    // val jwk = JWK.ecPrivate(ecPrivate, Algorithm.ES256).fold(throw _, identity)
    // val signature = Signature.getInstance("SHA256withECDSA");
    // signature.initSign(jwk.getPrivateKey.fold(throw _, identity))
    // signature.update(jws.compact.getBytes())
    // val sig = ByteVector.view(signature.sign())
    // println(s"EC sig: $sig")

  // test("Create JWS with rsa signature"):
  //   val jws = JWS(
  //     Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"),
  //     Base64String.unsafeOf(
  //       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  //     ),
  //     None
  //   )
  //   // openssl genrsa -out /tmp/keypair.pem 2048
  //   val rsakeyPem = """-----BEGIN PRIVATE KEY-----
  //       |MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDzXiJZ3Eng2dtv
  //       |3VauNMq6x96Bmk69mJqapADVWFZi1vKRn/DNCWLdCEyxR8lNwO5wWQKinfLZN1Ma
  //       |K8tPP+I55S6TkPtQslHHiN/Yehbpf/KuKlnVI1Tf1INyVU5LwwM1JwM/UyiZ19HS
  //       |8S/uxTc1oXsLyw8UUTAwHgXTMIweAdlmIsL5nskRYAzLS6QjJbXTjahCVJ75fNpw
  //       |rSXWZmKwjmsc20gD1iFrGkfsH6Zt50eyU8mmHo84ZhPGb7oF9XMYCSPArZy8YSZQ
  //       |aNTBqQ0EaivN8KykZRjKuZyVoBTshwwb3nh/u5LB9p0a5QeLZHDjHpDMmiCMEwXd
  //       |c+kVDUmfAgMBAAECggEAHdozLoCmE03F7A/jfRT+tTClK5KpC/q3JDbv3zupxRAG
  //       |yzQqToxTMze8aJacq8v5s5BHkXj8fAacS/6JPtxgPKfPMcy79ycYfvhcNOqs+tF2
  //       |DEUnpcxisd4YjaLHKuXt88woStFBjrV5iH2LWqeYYRzAwi6TV/OpjI1yO3ieB2QH
  //       |cJV9tuv7HAUTK9gGWyahQnkn4ZdB2cVPj8rMEis9cijbF/jx8GgfC2QDbz6eA4o/
  //       |RYcP9BW3TXQSVO5OMAt642+TRgIsOPIK5DyACxaRmnk1EQdRfkRAMRRvKGDFIiqk
  //       |s8/8CNrh4sHD+rNMTBOLE8fIuX6Oh/1152i7c91tOQKBgQD8VNOqdSt2cRhs+Ita
  //       |zH1v8SWszlGdFD9RNixQFHrAR85wKdeFBBF9uoUIudqSpH9a85zJbZJ+i6ijpk/g
  //       |gJtikl80qKWatK3vXGOmbaOt5XETYuqDBYhXvciaG4yfkBfxuvvvWd3dXRoeXusV
  //       |kLyVvVLDEYigoEEQEFEHvT4HJQKBgQD25/HgbPVwfxd4DT5ipkUIGi9Z2V6D4odH
  //       |JbqjOJBpVKVyDdvMowjF18g0O8ouHgp/jnWbttJ2KJqrnIWGtqBQ8l32LTnGIFbm
  //       |4viHmifOOdsk5MlCP/D1/3OAfhc7T2J/JxCWj0Zb04BH8ktvoGmoiThIWySbETzu
  //       |GVoy8S2EcwKBgQD48m/KEsOInVft2uER+gIfuRjkfsGCagF2DC5361yX68A+ZOme
  //       |8D6ZfrXVwBdm6ihEAWlESXhopT0CCAlygy/KdoK7n0+TbILWTp56Cl2cKWwAJm0c
  //       |Sw8TEciiUl/Q5QbalRIOOOlthndIU3k3045bZWgL0Hatkq3ePVrUed6CiQKBgETa
  //       |gdU4DWoFxyGvb8pK281aoAHKYFUfAuKQXu/NglgdRtX7j2QNwxCJEEegtM0Pi5Xu
  //       |wFVgMmjJAfkBeSsMGsD4FcPk8MuTkShp+yy1jIwyDi7HrmhPNH8lcaxPfWMIzErx
  //       |NesGoXRSEt/9bZP/g/d/7LYg1KB5uigb4c96+lqJAoGATyx/IJNtjx6hxiePEx07
  //       |cfjgy5bd6SB1NMuF7Jcx051IXEy0RM0DLfEdMImTgP/QNWJ1YlzNDjFaUXz2wIo8
  //       |C0PrOt9BO52soq5CCIEjV1qb9fpOG8mfxtUUu6WeP1pcNdZI6/Lx3eDL0wOurBLI
  //       |Gaz7tha0AjaXukBIPm8JcqM=
  //       |-----END PRIVATE KEY-----""".stripMargin

  //   val jwk = JWK.rsaPrivate(rsakeyPem, Algorithm.RS256).fold(throw _, identity)
  //   val signature = Signature.getInstance("SHA256withRSA");
  //   signature.initSign(jwk.getPrivateKey.fold(throw _, identity))
  //   signature.update(jws.compact.getBytes())
  //   val sig = ByteVector.view(signature.sign())
  //   println(s"RSA sig: $sig")

  extension (self: String) def noWhitespace = self.replaceAll("\\s+", "")
