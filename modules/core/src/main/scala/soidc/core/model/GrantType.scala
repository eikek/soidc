package soidc.core.model

import soidc.jwt.Uri

enum GrantType:
  case AuthorizationCode
  case Password
  case ClientCredentials
  case RefreshToken
  case DeviceCode
  case Custom(uri: Uri)

  def render: String = this match
    case Custom(uri) => uri.value
    case DeviceCode  => "urn:ietf:params:oauth:grant-type:device_code"
    case e           => Util.snakeCase(e.productPrefix)
