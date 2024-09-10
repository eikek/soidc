package soidc.jwt.json

object syntax
    extends FromJson.Syntax
    with ToJson.Syntax
    with JsonEncoder.Syntax
    with JsonDecoder.Syntax
