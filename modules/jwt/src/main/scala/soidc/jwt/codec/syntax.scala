package soidc.jwt.codec

object syntax
    extends FromJson.Syntax
    with ToJson.Syntax
    with ByteEncoder.Syntax
    with ByteDecoder.Syntax
