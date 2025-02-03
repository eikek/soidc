package soidc.jwt

object KeyData:

  // openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -inform pem -nocrypt -topk8 > /tmp/ec.private.pem
  // openssl ec -in /tmp/ec.private.pem -pubout -out /tmp/ec.public.pem
  val ecPrivate = """-----BEGIN PRIVATE KEY-----
                    |MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8kqABXEiSKJrc48y
                    |ljklhnT+2TDc8W43iC5MS27WaCShRANCAARorbyspEAgTEJlnhQCWT2w7yupFC9r
                    |ha176BXrQyuWNKvGOURmSuIfDLqRQj/n6hP2ZGzStq4RnUb9Nqwq6fWl
                    |-----END PRIVATE KEY-----""".stripMargin

  val ecPublic = """-----BEGIN PUBLIC KEY-----
                   |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaK28rKRAIExCZZ4UAlk9sO8rqRQv
                   |a4Wte+gV60MrljSrxjlEZkriHwy6kUI/5+oT9mRs0rauEZ1G/TasKun1pQ==
                   |-----END PUBLIC KEY-----""".stripMargin

  // openssl genrsa -out /tmp/keypair.pem 2048
  val rsaPem = """-----BEGIN PRIVATE KEY-----
                 |MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDzXiJZ3Eng2dtv
                 |3VauNMq6x96Bmk69mJqapADVWFZi1vKRn/DNCWLdCEyxR8lNwO5wWQKinfLZN1Ma
                 |K8tPP+I55S6TkPtQslHHiN/Yehbpf/KuKlnVI1Tf1INyVU5LwwM1JwM/UyiZ19HS
                 |8S/uxTc1oXsLyw8UUTAwHgXTMIweAdlmIsL5nskRYAzLS6QjJbXTjahCVJ75fNpw
                 |rSXWZmKwjmsc20gD1iFrGkfsH6Zt50eyU8mmHo84ZhPGb7oF9XMYCSPArZy8YSZQ
                 |aNTBqQ0EaivN8KykZRjKuZyVoBTshwwb3nh/u5LB9p0a5QeLZHDjHpDMmiCMEwXd
                 |c+kVDUmfAgMBAAECggEAHdozLoCmE03F7A/jfRT+tTClK5KpC/q3JDbv3zupxRAG
                 |yzQqToxTMze8aJacq8v5s5BHkXj8fAacS/6JPtxgPKfPMcy79ycYfvhcNOqs+tF2
                 |DEUnpcxisd4YjaLHKuXt88woStFBjrV5iH2LWqeYYRzAwi6TV/OpjI1yO3ieB2QH
                 |cJV9tuv7HAUTK9gGWyahQnkn4ZdB2cVPj8rMEis9cijbF/jx8GgfC2QDbz6eA4o/
                 |RYcP9BW3TXQSVO5OMAt642+TRgIsOPIK5DyACxaRmnk1EQdRfkRAMRRvKGDFIiqk
                 |s8/8CNrh4sHD+rNMTBOLE8fIuX6Oh/1152i7c91tOQKBgQD8VNOqdSt2cRhs+Ita
                 |zH1v8SWszlGdFD9RNixQFHrAR85wKdeFBBF9uoUIudqSpH9a85zJbZJ+i6ijpk/g
                 |gJtikl80qKWatK3vXGOmbaOt5XETYuqDBYhXvciaG4yfkBfxuvvvWd3dXRoeXusV
                 |kLyVvVLDEYigoEEQEFEHvT4HJQKBgQD25/HgbPVwfxd4DT5ipkUIGi9Z2V6D4odH
                 |JbqjOJBpVKVyDdvMowjF18g0O8ouHgp/jnWbttJ2KJqrnIWGtqBQ8l32LTnGIFbm
                 |4viHmifOOdsk5MlCP/D1/3OAfhc7T2J/JxCWj0Zb04BH8ktvoGmoiThIWySbETzu
                 |GVoy8S2EcwKBgQD48m/KEsOInVft2uER+gIfuRjkfsGCagF2DC5361yX68A+ZOme
                 |8D6ZfrXVwBdm6ihEAWlESXhopT0CCAlygy/KdoK7n0+TbILWTp56Cl2cKWwAJm0c
                 |Sw8TEciiUl/Q5QbalRIOOOlthndIU3k3045bZWgL0Hatkq3ePVrUed6CiQKBgETa
                 |gdU4DWoFxyGvb8pK281aoAHKYFUfAuKQXu/NglgdRtX7j2QNwxCJEEegtM0Pi5Xu
                 |wFVgMmjJAfkBeSsMGsD4FcPk8MuTkShp+yy1jIwyDi7HrmhPNH8lcaxPfWMIzErx
                 |NesGoXRSEt/9bZP/g/d/7LYg1KB5uigb4c96+lqJAoGATyx/IJNtjx6hxiePEx07
                 |cfjgy5bd6SB1NMuF7Jcx051IXEy0RM0DLfEdMImTgP/QNWJ1YlzNDjFaUXz2wIo8
                 |C0PrOt9BO52soq5CCIEjV1qb9fpOG8mfxtUUu6WeP1pcNdZI6/Lx3eDL0wOurBLI
                 |Gaz7tha0AjaXukBIPm8JcqM=
                 |-----END PRIVATE KEY-----""".stripMargin

  // openssl rsa -in rsa.priv.pem -pubout
  val rsaPub = """-----BEGIN PUBLIC KEY-----
                 |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA814iWdxJ4Nnbb91WrjTK
                 |usfegZpOvZiamqQA1VhWYtbykZ/wzQli3QhMsUfJTcDucFkCop3y2TdTGivLTz/i
                 |OeUuk5D7ULJRx4jf2HoW6X/yripZ1SNU39SDclVOS8MDNScDP1MomdfR0vEv7sU3
                 |NaF7C8sPFFEwMB4F0zCMHgHZZiLC+Z7JEWAMy0ukIyW1042oQlSe+XzacK0l1mZi
                 |sI5rHNtIA9YhaxpH7B+mbedHslPJph6POGYTxm+6BfVzGAkjwK2cvGEmUGjUwakN
                 |BGorzfCspGUYyrmclaAU7IcMG954f7uSwfadGuUHi2Rw4x6QzJogjBMF3XPpFQ1J
                 |nwIDAQAB
                 |-----END PUBLIC KEY-----""".stripMargin
