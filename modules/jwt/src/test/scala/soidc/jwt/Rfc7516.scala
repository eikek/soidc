package soidc.jwt

import javax.crypto.spec.SecretKeySpec

import scodec.bits.*
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.codec.*

object Rfc7516:

  object AppendixA {
    val plainText = "The true sign of intelligence is not knowledge but imagination."
    val plainTextBytes = ByteVector.encodeUtf8(plainText).fold(throw _, identity)

    val joseHeader: JoseHeader = JoseHeader.jwe()

    val contentEncKey: ByteVector =
      ByteVector[Int](177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
        212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252)

    val contentEncKeySpec =
      new SecretKeySpec(contentEncKey.toArray, "AES")

    val contentEncKeyEncrypted = Base64String.unsafeOf(
      "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe",
      "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb",
      "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV",
      "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8",
      "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi",
      "6UklfCpIMfIjf7iGdXKHzg"
    )

    val rsaKey = JWK
      .fromObj(
        JsonValue.emptyObj
          .replace(P.Kty, KeyType.RSA)
          .replace(
            RsaKey.Param.N,
            Base64String.unsafeOf(
              "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW",
              "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S",
              "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a",
              "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS",
              "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj",
              "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw"
            )
          )
          .replace(
            RsaKey.Param.E,
            Base64String.unsafeOf("AQAB")
          )
          .replace(
            RsaKey.Param.D,
            Base64String.unsafeOf(
              "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N",
              "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9",
              "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk",
              "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl",
              "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd",
              "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ"
            )
          )
          .replace(
            RsaKey.Param.P,
            Base64String.unsafeOf(
              "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-",
              "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf",
              "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0"
            )
          )
          .replace(
            RsaKey.Param.Q,
            Base64String.unsafeOf(
              "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm",
              "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX",
              "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc"
            )
          )
      )
      .fold(throw _, identity)

    val publicKey = RsaKey.createPublicKey(rsaKey).fold(throw _, identity)
    val privateKey = RsaKey.createPrivateKey(rsaKey).fold(throw _, identity)

    val initVector: ByteVector =
      ByteVector[Int](227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219)

    val aad: ByteVector = ByteVector[Int](101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74,
      83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
      54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81)

    val finalJWE: JWE = JWE
      .fromString(
        """eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"""
      )
      .fold(sys.error, identity)
  }
