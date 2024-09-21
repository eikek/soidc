package soidc.jwt

trait StandardClaims[C]:
  def notBefore(claims: C): Option[NumericDate]
  def expirationTime(claims: C): Option[NumericDate]
  def setExpirationTime(claims: C, exp: NumericDate): C
  def issuer(claims: C): Option[StringOrUri]
  def subject(claims: C): Option[StringOrUri]
  def jwtId(claims: C): Option[String]

object StandardClaims:
  def apply[C](using sc: StandardClaims[C]): StandardClaims[C] = sc

  def apply[C](
      nbf: C => Option[NumericDate],
      exp: C => Option[NumericDate],
      iss: C => Option[StringOrUri],
      sub: C => Option[StringOrUri],
      jti: C => Option[String],
      setExp: (C, NumericDate) => C
  ): StandardClaims[C] =
    new StandardClaims[C] {
      def expirationTime(claims: C): Option[NumericDate] = exp(claims)
      def setExpirationTime(claims: C, exp: NumericDate): C = setExp(claims, exp)
      def notBefore(claims: C): Option[NumericDate] = nbf(claims)
      def issuer(claims: C): Option[StringOrUri] = iss(claims)
      def subject(claims: C): Option[StringOrUri] = sub(claims)
      def jwtId(claims: C): Option[String] = jti(claims)
    }
