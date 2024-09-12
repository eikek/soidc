package soidc.jwt

trait StandardClaims[C]:
  def notBefore(claims: C): Option[NumericDate]
  def expirationTime(claims: C): Option[NumericDate]
  def issuer(claims: C): Option[StringOrUri]

object StandardClaims:
  def apply[C](using sc: StandardClaims[C]): StandardClaims[C] = sc

  def apply[C](
      nbf: C => Option[NumericDate],
      exp: C => Option[NumericDate],
      iss: C => Option[StringOrUri]
  ): StandardClaims[C] =
    new StandardClaims[C] {
      def expirationTime(claims: C): Option[NumericDate] = exp(claims)
      def notBefore(claims: C): Option[NumericDate] = nbf(claims)
      def issuer(claims: C): Option[StringOrUri] = iss(claims)
    }
