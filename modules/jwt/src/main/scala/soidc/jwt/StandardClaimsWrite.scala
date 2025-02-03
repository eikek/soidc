package soidc.jwt

trait StandardClaimsWrite[C]:
  def setExpirationTime(claims: C, exp: NumericDate): C
  def setIssuer(claims: C, issuer: StringOrUri): C

object StandardClaimsWrite:
  def apply[C](using sc: StandardClaimsWrite[C]): StandardClaimsWrite[C] = sc

  def apply[C](
      setExp: (C, NumericDate) => C,
      setIss: (C, StringOrUri) => C
  ): StandardClaimsWrite[C] =
    new StandardClaimsWrite[C] {
      def setExpirationTime(claims: C, exp: NumericDate): C = setExp(claims, exp)
      def setIssuer(claims: C, iss: StringOrUri): C = setIss(claims, iss)
    }
