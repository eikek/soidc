package soidc.core

import cats.Applicative
import cats.effect.std.Console
import cats.syntax.all.*

trait Logger[F[_]]:
  def debug(message: String): F[Unit]

object Logger:
  def nop[F[_]: Applicative]: Logger[F] =
    new Logger[F] {
      def debug(message: String): F[Unit] = ().pure[F]
    }

  def stdout[F[_]: Console]: Logger[F] =
    new Logger[F] {
      def debug(message: String): F[Unit] =
        Console[F].println(message)
    }

  def stderr[F[_]: Console]: Logger[F] =
    new Logger[F] {
      def debug(message: String): F[Unit] =
        Console[F].errorln(message)
    }
