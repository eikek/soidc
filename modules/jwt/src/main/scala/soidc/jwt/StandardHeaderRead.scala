package soidc.jwt

trait StandardHeaderRead[H]:
  def keyId(header: H): Option[KeyId]
  def algorithm(header: H): Option[Algorithm]

object StandardHeaderRead:
  def apply[H](using sh: StandardHeaderRead[H]): StandardHeaderRead[H] = sh

  def apply[H](
      kid: H => Option[KeyId],
      alg: H => Option[Algorithm]
  ): StandardHeaderRead[H] =
    new StandardHeaderRead[H] {
      def keyId(header: H): Option[KeyId] = kid(header)
      def algorithm(header: H): Option[Algorithm] = alg(header)
    }
