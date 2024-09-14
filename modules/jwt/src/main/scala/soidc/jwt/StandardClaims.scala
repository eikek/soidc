package soidc.jwt

trait StandardClaims[C]:
  def notBefore(claims: C): Option[NumericDate]
  def expirationTime(claims: C): Option[NumericDate]
  def issuer(claims: C): Option[StringOrUri]
  def jwtId(claims: C): Option[String]

object StandardClaims:
  def apply[C](using sc: StandardClaims[C]): StandardClaims[C] = sc

  def apply[C](
      nbf: C => Option[NumericDate],
      exp: C => Option[NumericDate],
      iss: C => Option[StringOrUri],
      jti: C => Option[String]
  ): StandardClaims[C] =
    new StandardClaims[C] {
      def expirationTime(claims: C): Option[NumericDate] = exp(claims)
      def notBefore(claims: C): Option[NumericDate] = nbf(claims)
      def issuer(claims: C): Option[StringOrUri] = iss(claims)
      def jwtId(claims: C): Option[String] = jti(claims)
    }
