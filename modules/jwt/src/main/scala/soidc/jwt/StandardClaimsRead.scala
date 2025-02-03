package soidc.jwt

trait StandardClaimsRead[C]:
  def issuer(claims: C): Option[StringOrUri]
  def subject(claims: C): Option[StringOrUri]
  def jwtId(claims: C): Option[String]
  def notBefore(claims: C): Option[NumericDate]
  def expirationTime(claims: C): Option[NumericDate]

object StandardClaimsRead:

  def apply[C](using sc: StandardClaimsRead[C]): StandardClaimsRead[C] = sc

  def apply[C](
      nbf: C => Option[NumericDate],
      exp: C => Option[NumericDate],
      iss: C => Option[StringOrUri],
      sub: C => Option[StringOrUri],
      jti: C => Option[String]
  ): StandardClaimsRead[C] =
    new StandardClaimsRead[C] {
      def expirationTime(claims: C): Option[NumericDate] = exp(claims)
      def notBefore(claims: C): Option[NumericDate] = nbf(claims)
      def issuer(claims: C): Option[StringOrUri] = iss(claims)
      def subject(claims: C): Option[StringOrUri] = sub(claims)
      def jwtId(claims: C): Option[String] = jti(claims)
    }
