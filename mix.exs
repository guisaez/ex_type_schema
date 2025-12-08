defmodule ExTypeSchema.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_type_schema,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {ExTypeSchema.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_json_schema, "~> 0.10"},
      {:jason, "~> 1.4"}
    ]
  end
end
