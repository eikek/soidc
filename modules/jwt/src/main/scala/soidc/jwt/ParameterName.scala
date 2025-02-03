package soidc.jwt

trait ParameterName:
  def key: String
  def description: String
  def is(other: ParameterName): Boolean = key == other.key

object ParameterName:

  private case class Impl(key: String, description: String) extends ParameterName

  def of(key: String, description: String = ""): ParameterName = Impl(key, description)
