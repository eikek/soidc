package soidc.jwt

enum RegisteredParameterName(val key: String, val description: String)
    extends ParameterName:
  case Alg extends RegisteredParameterName("alg", "Algorithm")
  case Jku extends RegisteredParameterName("jku", "JWK Set URL")
  case Jwk extends RegisteredParameterName("jwk", "JSON Web Key")
  case Kid extends RegisteredParameterName("kid", "Key ID")
  case Kty extends RegisteredParameterName("kty", "Key Type")
  case Use extends RegisteredParameterName("use", "Key Use")
  case KeyOps extends RegisteredParameterName("key_ops", "Key Operations")
  case X5u extends RegisteredParameterName("x5u", "X.509 URL")
  case X5c extends RegisteredParameterName("x5c", "X.509 Certificate Chain")
  case X5t extends RegisteredParameterName("x5t", "X.509 Certificate SHA-1 Thumbprint")
  case X5t256
      extends RegisteredParameterName("x5t#S256", "X.509 Certificate SHA-256 Thumbprint")
  case Typ extends RegisteredParameterName("typ", "Type")
  case Cty extends RegisteredParameterName("cty", "Content Type")
  case Crit extends RegisteredParameterName("crit", "Critical")
  case Iss extends RegisteredParameterName("iss", "Issuer")
  case Sub extends RegisteredParameterName("sub", "Subject")
  case Aud extends RegisteredParameterName("aud", "Audience")
  case Exp extends RegisteredParameterName("exp", "Expiration Time")
  case Nbf extends RegisteredParameterName("nbf", "Not Before")
  case Jti extends RegisteredParameterName("jti", "JWT ID")
  case Iat extends RegisteredParameterName("iat", "Issued At")
  case Enc extends RegisteredParameterName("enc", "Encryption Algorithm")
  case Zip extends RegisteredParameterName("zip", "Compression Algorithm")
