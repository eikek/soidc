package soidc.jwt

trait StandardHeader[H]:
  def keyId(header: H): Option[KeyId]
  def algorithm(header: H): Option[Algorithm]

object StandardHeader:
  def apply[H](using sh: StandardHeader[H]): StandardHeader[H] = sh

  def apply[H](
      kid: H => Option[KeyId],
      alg: H => Option[Algorithm]
  ): StandardHeader[H] =
    new StandardHeader[H] {
      def keyId(header: H): Option[KeyId] = kid(header)
      def algorithm(header: H): Option[Algorithm] = alg(header)
    }
