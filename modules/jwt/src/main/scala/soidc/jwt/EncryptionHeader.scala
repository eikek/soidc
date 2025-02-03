package soidc.jwt

trait EncryptionHeader[H]:
  def algorithm(header: H): Option[Algorithm.Encrypt]
  def encryptionAlgorithm(header: H): Option[ContentEncryptionAlgorithm]

object EncryptionHeader:
  def apply[H](using sh: EncryptionHeader[H]): EncryptionHeader[H] = sh

  def apply[H](
      alg: H => Option[Algorithm.Encrypt],
      enc: H => Option[ContentEncryptionAlgorithm]
  ): EncryptionHeader[H] =
    new EncryptionHeader[H] {
      def algorithm(header: H): Option[Algorithm.Encrypt] = alg(header)
      def encryptionAlgorithm(header: H): Option[ContentEncryptionAlgorithm] = enc(header)
    }
