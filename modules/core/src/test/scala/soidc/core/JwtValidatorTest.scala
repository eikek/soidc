package soidc.core

import scala.util.Try

import munit.FunSuite
import soidc.jwt.*

class JwtValidatorTest extends FunSuite:

  def makeJwt[H, C](h: H, c: C): JWSDecoded[H, C] =
    val jws = JWS(Base64String.unsafeOf("YQ"), Base64String.unsafeOf("YQ"))
    JWSDecoded(jws, h, c)

  val fail1 = Validate.FailureReason.GenericReason("1")
  val fail2 = Validate.FailureReason.GenericReason("2")

  test("concat runs both validators and combines their results"):
    val v1 = JwtValidator.invalid[Try, Unit, Unit](fail1)
    val v2 = JwtValidator.invalid[Try, Unit, Unit](fail2)

    val jws = makeJwt((), ())
    val r = (v1 ++ v2).validate(jws).get.get
    assertEquals(r, Validate.Result.failed(fail1, fail2))

  test("andThem runs both validators and combines their results"):
    val v1 = JwtValidator.invalid[Try, Unit, Unit](fail1)
    val v2 = JwtValidator.invalid[Try, Unit, Unit](fail2)

    val jws = makeJwt((), ())
    val r = v1.andThen(_ => v2).validate(jws).get.get
    assertEquals(r, Validate.Result.failed(fail1, fail2))

  test("orElse runs other variant on not-applicable"):
    val v1 = JwtValidator.notApplicable[Try, Unit, Unit]
    val v2 = JwtValidator.alwaysValid[Try, Unit, Unit]

    val jws = makeJwt((), ())
    val r = v1.orElse(v2).validate(jws).get.get
    assertEquals(r, Validate.Result.success)

  test("orElse doesn't run other variant if first fails"):
    val v1 = JwtValidator.invalid[Try, Unit, Unit](fail1)
    val v2 = JwtValidator.alwaysValid[Try, Unit, Unit]
    val jws = makeJwt((), ())
    val r = v1.orElse(v2).validate(jws).get.get
    assertEquals(r, Validate.Result.failed(fail1))

  test("invalidToNotApplicable converts invalid to not applicable"):
    val v1 = JwtValidator.invalid[Try, Unit, Unit](fail1).invalidToNotApplicable
    val jws = makeJwt((), ())
    val r = v1.validate(jws).get
    assertEquals(r, JwtValidator.Result.notApplicable)

  test("scoped filters validation"):
    val v1 = JwtValidator
      .invalid[Try, Unit, Unit](fail1)
      .scoped(_.jws.header == Base64String.unsafeOf("Yg"))
    val r = v1.validate(makeJwt((), ())).get
    assertEquals(r, None)
