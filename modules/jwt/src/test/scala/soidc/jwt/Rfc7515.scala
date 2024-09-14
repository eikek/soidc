package soidc.jwt

/** Examples from https://datatracker.ietf.org/doc/html/rfc7515 (appendix) */
object Rfc7515:

  object Appendix1 {
    val header: JoseHeader =
      JoseHeader.empty.withAlgorithm(Algorithm.HS256)

    val header64: Base64String =
      Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9")

    val claim = SimpleClaims.empty
      .withIssuer(StringOrUri("joe"))
      .withExpirationTime(NumericDate.seconds(1300819380L))
      .withValue(ParameterName.of("http://example.com/is_root"), true)

    val claim64: Base64String =
      Base64String.unsafeOf(
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo",
        "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
      )

    val symmetricKey: JWK =
      JWK
        .symmetric(
          Base64String.unsafeOf(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_",
            "T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
          ),
          Algorithm.HS256
        )
        .withKeyId(KeyId.unsafeFromString("appendix1"))

    val signature: Base64String =
      Base64String.unsafeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

    val jws = JWS(header64, claim64, Some(signature))
    val jwsDecoded = JWSDecoded(jws, header, claim)
  }

  object Appendix2 {
    val header: JoseHeader = JoseHeader.empty.withAlgorithm(Algorithm.RS256)
    val header64: Base64String = Base64String.unsafeOf("eyJhbGciOiJSUzI1NiJ9")

    val claim: SimpleClaims = Appendix1.claim
    val claim64: Base64String = Appendix1.claim64

    val rsaKey: JWK = JWK(KeyType.RSA)
      .withAlgorithm(Algorithm.RS256)
      .withKeyId(KeyId.unsafeFromString("appendix2"))
      .withValue(
        RsaKey.Param.N,
        Base64String.unsafeOf(
          "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4",
          "qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2j",
          "Z47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7W",
          "TBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK",
          "-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
        )
      )
      .withValue(RsaKey.Param.E, Base64String.unsafeOf("AQAB"))
      .withValue(
        RsaKey.Param.D,
        Base64String.unsafeOf(
          "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKM",
          "gvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaY",
          "LU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0",
          "ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDV",
          "ZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
        )
      )
      .withValue(
        RsaKey.Param.P,
        Base64String.unsafeOf(
          "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58B",
          "Q3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn",
          "-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
        )
      )
      .withValue(
        RsaKey.Param.Q,
        Base64String.unsafeOf(
          "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1",
          "ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTl",
          "tRJ11BKBBypeeF6689rjcJIDEz9RWdc"
        )
      )

    val signature: Base64String =
      Base64String.unsafeOf(
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm",
        "4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--",
        "f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383Lc",
        "OLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUi",
        "pUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
      )

    val jws = JWS(header64, claim64, Some(signature))
    val jwsDecoded = JWSDecoded(jws, header, claim)
  }

  object Appendix3 {
    val header: JoseHeader = JoseHeader.empty.withAlgorithm(Algorithm.ES256)
    val header64: Base64String = Base64String.unsafeOf("eyJhbGciOiJFUzI1NiJ9")

    val claim: SimpleClaims = Appendix1.claim
    val claim64: Base64String = Appendix1.claim64

    val ecKey: JWK =
      JWK(KeyType.EC)
        .withAlgorithm(Algorithm.ES256)
        .withKeyId(KeyId.unsafeFromString("appendix3"))
        .withValue(EcKey.ECParam.Crv, Curve.P256)
        .withValue(
          EcKey.ECParam.X,
          Base64String.unsafeOf("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
        )
        .withValue(
          EcKey.ECParam.Y,
          Base64String.unsafeOf("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
        )
        .withValue(
          EcKey.ECParam.D,
          Base64String.unsafeOf("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")
        )

    val signature: Base64String = Base64String.unsafeOf(
      "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    )

    val publicPem = """-----BEGIN PUBLIC KEY-----
                      |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV7
                      |6e8Tus9uPHvRVEXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==
                      |-----END PUBLIC KEY-----""".stripMargin

    val privatePem = """-----BEGIN EC PRIVATE KEY-----
                       |MCUCAQEEII6bEJ5xkJi/mASH3x9dd+nLKWBuvtImO19XwhPfhPSy
                       |-----END EC PRIVATE KEY-----""".stripMargin

    val jws = JWS(header64, claim64, Some(signature))
    val jwsDecoded = JWSDecoded(jws, header, claim)
  }

  object Appendix4 {
    val header: JoseHeader = JoseHeader.empty.withAlgorithm(Algorithm.ES512)
    val header64: Base64String = Base64String.unsafeOf("eyJhbGciOiJFUzUxMiJ9")

    val claim64: Base64String = Base64String.unsafeOf("UGF5bG9hZA")
    val claim: String = "Payload"

    val ecKey: JWK =
      JWK(KeyType.EC)
        .withAlgorithm(Algorithm.ES512)
        .withKeyId(KeyId.unsafeFromString("appendix4"))
        .withValue(EcKey.ECParam.Crv, Curve.P521)
        .withValue(
          EcKey.ECParam.X,
          Base64String.unsafeOf(
            "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"
          )
        )
        .withValue(
          EcKey.ECParam.Y,
          Base64String.unsafeOf(
            "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"
          )
        )
        .withValue(
          EcKey.ECParam.D,
          Base64String.unsafeOf(
            "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
          )
        )

    val signature: Base64String = Base64String.unsafeOf(
      "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI",
      "-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO",
      "7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
    )

    val jws = JWS(header64, claim64, Some(signature))
    val jwsDecoded = JWSDecoded(jws, header, claim)
  }
