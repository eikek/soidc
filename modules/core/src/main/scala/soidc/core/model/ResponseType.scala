package soidc.core.model

enum ResponseType:
  case Code
  case Token
  case Custom(name: String)

  def render: String = this match
    case Code      => "code"
    case Token     => "token"
    case Custom(n) => n
