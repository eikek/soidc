package soidc.core.auth

private object Util:

  def snakeCase(str: String): String =
    if (str.isEmpty()) str
    else
      val builder = new StringBuilder
      builder += str.charAt(0).toLower
      str.drop(1).foreach { c =>
        if (c.isUpper) builder += '_'
        builder += c.toLower
      }
      builder.toString()

  def lowerFirst(str: String): String =
    if (str.isEmpty() || str.charAt(0).isLower) str
    else str.updated(0, str.charAt(0).toLower)
