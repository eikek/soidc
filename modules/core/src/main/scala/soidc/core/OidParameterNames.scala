package soidc.core

import soidc.jwt.ParameterName

enum OidParameterNames(val key: String) extends ParameterName:
  case Nonce extends OidParameterNames("nonce")
  case EmailVerified extends OidParameterNames("email_verified")
  case Name extends OidParameterNames("name")
  case PreferredUsername extends OidParameterNames("preferred_username")
  case GivenName extends OidParameterNames("given_name")
  case FamilyName extends OidParameterNames("family_name")
  case SessionState extends OidParameterNames("session_state")

  val description: String = ""
