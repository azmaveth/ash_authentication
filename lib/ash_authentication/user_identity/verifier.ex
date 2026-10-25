# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.UserIdentity.Verifier do
  @moduledoc """
  The user identity verifier.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.UserIdentity.Info
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(_), do: true

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(_), do: false

  @doc false
  @impl true
  @spec after_compile? :: boolean
  def after_compile?, do: true

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with :ok <- validate_domain_presence(dsl_state),
         :ok <- validate_user_resource(dsl_state) do
      validate_read_action(dsl_state)
    end
  end

  # Checked here rather than in the transformer, which runs before
  # `defaults [:read]` is expanded into an action.
  defp validate_read_action(dsl_state) do
    with {:ok, action_name} <- Info.user_identity_read_action_name(dsl_state),
         {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      validate_field_in_values(action, :primary?, [true])
    end
  end

  defp validate_domain_presence(dsl_state) do
    with {:ok, domain} <- Info.user_identity_domain(dsl_state) do
      assert_is_domain(domain)
    end
  end

  defp validate_user_resource(dsl_state) do
    with {:ok, user_resource} <- Info.user_identity_user_resource(dsl_state) do
      assert_resource_has_extension(user_resource, AshAuthentication)
    end
  end
end
