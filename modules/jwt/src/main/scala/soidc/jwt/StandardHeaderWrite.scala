package soidc.jwt

trait StandardHeaderWrite[H]:
  def setAlgorithm(header: H, algorithm: Algorithm): H

object StandardHeaderWrite:
  def apply[H](using sh: StandardHeaderWrite[H]): StandardHeaderWrite[H] = sh

  def apply[H](
      setAlg: (H, Algorithm) => H
  ): StandardHeaderWrite[H] =
    new StandardHeaderWrite[H] {
      def setAlgorithm(header: H, alg: Algorithm): H = setAlg(header, alg)
    }
