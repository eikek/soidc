package soidc.jwt

import scodec.bits.ByteVector

private object EcDerCodec:
  /** Converts a EC signature in DER format into the "R+S" format required by JWT */
  def derSignatureToRS(
      der: ByteVector,
      outLen: Int
  ): Either[JwtError.InvalidECSignature, ByteVector] =
    (for
      (rem0, _) <- der.consume(1)(bv =>
        Either.cond(bv.head == 0x30, (), s"Invalid DER signature: header byte: $bv")
      )
      offset = if (rem0.head >= 0) 2 else 3
      (rem1, rLen) <- rem0.consume(offset + 1)(bv => Right(bv.last.toLong))
//      _ = println(s"rlen = $rLen")
      intLen = outLen / 2
      (rem2, r) <- rem1.consume(rLen) { bv =>
        val bv1 = bv.dropWhile(_ == 0)
        Right(if (intLen > bv1.size) bv1.padLeft(intLen) else bv1)
      }
      (rem3, sLen) <- rem2.consume(2)(bv => Right(bv.last.toLong))
//      _ = println(s"slen = $sLen")
      (rem4, s) <- rem3.consume(sLen)(bv =>
        val bv1 = bv.dropWhile(_ == 0)
        Right(if (intLen > bv1.size) bv1.padLeft(intLen) else bv1)
      )
//      _ = println(s"inLen = $intLen\nr = $r\ns = $s")
      _ <- Either.cond(rem4.isEmpty, (), "Invalid DER signature")
    yield r ++ s).left.map(msg => JwtError.InvalidECSignature(der, Some(msg)))

  /** Converts a EC signature in "R+S" format into DER */
  def rsSignatureToDER(
      sig: ByteVector
  ): Either[JwtError.InvalidECSignature, ByteVector] =
    def twoc(b: ByteVector) =
      val b1 = b.dropWhile(_ == 0)
      if (b1.nonEmpty && b1.head < 0) 0.toByte +: b1
      else b1

    val (r, s) = {
      val (r1, s1) = sig.splitAt(sig.size / 2)
      (twoc(r1), twoc(s1))
    }
    val len = 2 + r.size + 2 + s.size
    val header = {
      val h = ByteVector(0x30.toByte)
      if (len >= 128) h :+ 0x81.toByte else h
    }
    if (len > 255) Left(JwtError.InvalidECSignature(sig))
    else
      Right(
        header ++ ByteVector(len.toByte) ++ ByteVector(
          2.toByte,
          r.length.toByte
        ) ++ r ++ ByteVector(2.toByte, s.length.toByte) ++ s
      )
