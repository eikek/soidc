package soidc.jwt

trait StandardClaims[C] extends StandardClaimsRead[C] with StandardClaimsWrite[C]

object StandardClaims:
  def apply[C](using sc: StandardClaims[C]): StandardClaims[C] = sc

  given [C](using
      sr: StandardClaimsRead[C],
      sw: StandardClaimsWrite[C]
  ): StandardClaims[C] =
    new StandardClaims[C] {
      def expirationTime(claims: C): Option[NumericDate] = sr.expirationTime(claims)
      def issuer(claims: C): Option[StringOrUri] = sr.issuer(claims)
      def jwtId(claims: C): Option[String] = sr.jwtId(claims)
      def notBefore(claims: C): Option[NumericDate] = sr.notBefore(claims)
      def subject(claims: C): Option[StringOrUri] = sr.subject(claims)
      def setExpirationTime(claims: C, exp: NumericDate): C =
        sw.setExpirationTime(claims, exp)
      def setIssuer(claims: C, issuer: StringOrUri): C = sw.setIssuer(claims, issuer)
    }
