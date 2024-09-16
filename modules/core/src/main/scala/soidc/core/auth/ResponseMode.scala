package soidc.core.auth

enum ResponseMode:
  case Query
  case Fragment

  def render: String = Util.snakeCase(productPrefix)

  def isDefault: Boolean = this == ResponseMode.default

object ResponseMode:
  val default: ResponseMode = ResponseMode.Query
