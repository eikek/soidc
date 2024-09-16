package soidc.core.auth

enum ResponseType:
  case Code
  case Token
  case Custom(name: String)

  def render: String = this match
    case Code      => "code"
    case Token     => "token"
    case Custom(n) => n
