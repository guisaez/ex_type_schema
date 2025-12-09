defmodule ExTypeSchema do
  @moduledoc """
  Registry for loading and processing type schemas from JSON files.

  Uses two ETS tables:
  - @table_type_schema_registry: Stores raw JSON-like object representation (before parsing)
  - @table_type_json_registry: Stores fully parsed JSON Schema (after processing)

  Both tables use schema names (filenames without .json) as keys.
  """

  @table_type_schema_registry :type_schema_registry
  @table_type_json_registry :type_json_schema_registry

  def init do
    for table_name <- [@table_type_schema_registry, @table_type_json_registry] do
      case :ets.whereis(table_name) do
        :undefined ->
          :ets.new(table_name, [
            :named_table,
            :set,
            :public,
            read_concurrency: true,
            write_concurrency: true
          ])

          :ok

        _tid ->
          :ok
      end
    end
  end

  @doc """
  Loads a schema file from the given directory.
  Returns the fully processed JSON Schema with all nested references resolved.

  ## Examples

      iex> ExTypeSchema.Registry.load_schema_file("priv/schemas", "user")
      {:ok, %{"type" => "object", "properties" => ...}}
  """
  def load_schema_file(dir, schema) do
    filename = Path.join(dir, "#{schema}.json")

    with {:ok, processed_schema} <- parse_schema(dir, schema, filename) do
      {:ok, processed_schema}
    end
  end

  defp get_raw_schema(dir, schema) do
    case :ets.lookup(@table_type_schema_registry, schema) do
      [{^schema, raw_schema}] ->
        # Already loaded, return it
        {:ok, raw_schema}

      [] ->
        # Not in registry, load from file
        filename = Path.join(dir, "#{schema}.json")

        case File.read(filename) do
          {:ok, content} ->
            case Jason.decode(content) do
              {:ok, raw_schema} ->
                # Store raw schema in registry
                :ets.insert(@table_type_schema_registry, {schema, raw_schema})
                {:ok, raw_schema}

              {:error, _} ->
                {:error, :invalid_json}
            end

          {:error, _} ->
            {:error, :file_not_found}
        end
    end
  end

  defp get_parsed_schema(schema) do
    case :ets.lookup(@table_type_json_registry, schema) do
      [{^schema, parsed_schema}] ->
        {:ok, parsed_schema}

      [] ->
        :not_processed
    end
  end

  def parse_schema(dir, schema, _filename) do
    # Check if already parsed
    case get_parsed_schema(schema) do
      {:ok, parsed_schema} ->
        # Already processed, return it
        {:ok, parsed_schema}

      :not_processed ->
        # Need to process
        with {:ok, raw_schema = %{"properties" => props}} <- get_raw_schema(dir, schema) do
          # Mark as being processed (store a placeholder to detect circular refs)
          :ets.insert(@table_type_json_registry, {schema, :processing})

          {new_props, required_fields} =
            inflate_props(Map.keys(props), dir, props, [])

          result =
            Map.merge(raw_schema, %{
              "properties" => new_props,
              "additionalProperties" => Map.get(raw_schema, "additionalProperties", false)
            })
            |> add_required_fields(required_fields)

          # Store the fully processed schema
          :ets.insert(@table_type_json_registry, {schema, result})

          {:ok, result}
        else
          {:ok, _raw_schema} ->
            {:error, :missing_parent_object_properties}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp inflate_props([], _, result, required), do: {result, required}

  defp inflate_props([key | rest], dir, props, required) do
    prop_map = Map.get(props, key)
    is_required = Map.get(prop_map, "required", false)

    # Process the property and remap its type
    new_prop_map = remap_type(Map.get(prop_map, "type"), prop_map, dir)

    # Update required list if this field is required
    new_required = if is_required, do: [key | required], else: required

    # Remove the "required" key from the property map (it goes in the schema-level required array)
    cleaned_prop_map = Map.delete(new_prop_map, "required")

    inflate_props(rest, dir, Map.put(props, key, cleaned_prop_map), new_required)
  end

  defp remap_type("atom", map, _), do: Map.put(map, "type", "string")

  defp remap_type("binary", map, _), do: Map.put(map, "type", "string")

  defp remap_type("any", map, _),
    do: Map.put(map, "type", ["number", "string", "boolean", "object", "array", "null"])

  defp remap_type("object", map, dir) do
    case Map.get(map, "object_type") do
      nil ->
        map

      object_type ->
        inflated = inflate_object(dir, object_type)
        # Remove object_type and replace with the inflated schema
        map
        |> Map.delete("object_type")
        |> Map.merge(inflated)
    end
  end

  defp remap_type("array", map, dir) do
    case Map.get(map, "items") do
      nil ->
        map

      array_type ->
        case Map.get(array_type, "object_type") do
          nil ->
            # Just remap the array item type
            new_items = remap_type(Map.get(array_type, "type"), array_type, dir)
            Map.put(map, "items", new_items)

          object_type ->
            # Inflate the nested object type
            new_array_type = inflate_object(dir, object_type)
            Map.put(map, "items", new_array_type)
        end
    end
  end

  defp remap_type(_, map, _), do: map

  defp inflate_object(dir, object_type) do
    # Check if this schema is currently being processed (circular reference)
    case get_parsed_schema(object_type) do
      {:ok, :processing} ->
        # Circular reference detected - return a $ref
        %{"$ref" => "#/definitions/#{object_type}"}

      {:ok, parsed_schema} ->
        # Already fully processed, use it
        parsed_schema

      :not_processed ->
        # Need to process this nested schema
        filename = Path.join(dir, "#{object_type}.json")

        case parse_schema(dir, object_type, filename) do
          {:ok, parsed_schema} ->
            parsed_schema

          {:error, error} ->
            throw({:inflate_error, error, object_type})
        end
    end
  end

  defp add_required_fields(map, []), do: map
  defp add_required_fields(map, required), do: Map.put(map, "required", required)

  @doc """
  Retrieves a processed schema by name.

  ## Examples

      iex> ExTypeSchema.Registry.get_schema("user")
      {:ok, %{"type" => "object", ...}}
  """
  def get_schema(schema) do
    case :ets.lookup(@table_type_json_registry, schema) do
      [{^schema, :processing}] ->
        {:error, :currently_processing}

      [{^schema, processed_schema}] ->
        {:ok, processed_schema}

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Retrieves a raw schema by name.
  """
  def get_raw_schema(schema) do
    case :ets.lookup(@table_type_schema_registry, schema) do
      [{^schema, raw_schema}] ->
        {:ok, raw_schema}

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Lists all registered schemas (parsed).
  """
  def list_schemas do
    :ets.tab2list(@table_type_json_registry)
    |> Enum.map(fn {schema, _} -> schema end)
    |> Enum.filter(&is_binary/1)
  end

  @doc """
  Lists all raw schemas.
  """
  def list_raw_schemas do
    :ets.tab2list(@table_type_schema_registry)
    |> Enum.map(fn {schema, _} -> schema end)
  end

  @doc """
  Clears all schemas from both registries.
  """
  def clear_all do
    :ets.delete_all_objects(@table_type_schema_registry)
    :ets.delete_all_objects(@table_type_json_registry)
    :ok
  end

  @doc """
  Loads all schema files from a directory.

  ## Examples

      iex> ExTypeSchema.Registry.load_schemas_from_directory("priv/schemas")
      {:ok, "Loaded 3 schemas"}
  """
  def load_schemas_from_directory(dir) do
    unless File.dir?(dir) do
      {:error, "Directory not found: #{dir}"}
    else
      dir
      |> Path.join("*.json")
      |> Path.wildcard()
      |> Enum.map(fn file_path ->
        schema_name = Path.basename(file_path, ".json")

        case parse_schema(dir, schema_name, file_path) do
          {:ok, _schema} -> {:ok, schema_name}
          {:error, reason} -> {:error, {schema_name, reason}}
        end
      end)
      |> Enum.reduce({[], []}, fn
        {:ok, name}, {success, errors} -> {[name | success], errors}
        {:error, reason}, {success, errors} -> {success, [reason | errors]}
      end)
      |> case do
        {success, []} ->
          {:ok, "Loaded #{length(success)} schemas"}

        {success, errors} ->
          {:partial,
           "Loaded #{length(success)} schemas, #{length(errors)} errors: #{inspect(errors)}"}
      end
    end
  end

  @doc """
  Validates a map against a schema type.

  The schema parameter should be the type name (e.g., "user")
  which corresponds to a loaded schema file (e.g., user.json).

  Returns :ok if validation passes, or {:error, errors} with detailed error messages.

  ## Examples

      iex> ExTypeSchema.Registry.validate("user", %{"name" => "John", "age" => 30})
      :ok

      iex> ExTypeSchema.Registry.validate("user", %{"age" => "invalid"})
      {:error, [%{message: "Type mismatch...", path: "#/age"}]}
  """
  def validate(schema_type, data) when is_binary(schema_type) and is_map(data) do
    case get_schema(schema_type) do
      {:ok, json_schema} ->
        # Resolve and validate using ExJsonSchema
        try do
          resolved_schema = ExJsonSchema.Schema.resolve(json_schema)

          data_ = data |> Enum.map(fn {k, v} -> {to_string(k), v} end) |> Map.new()

          case ExJsonSchema.Validator.validate(resolved_schema, data_) do
            :ok ->
              :ok

            {:error, validation_errors} ->
              {:error, format_validation_errors(validation_errors)}
          end
        rescue
          e -> {:error, "Schema resolution error: #{Exception.message(e)}"}
        end

      {:error, :not_found} ->
        {:error, "Schema type '#{schema_type}' not found in registry"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def validate(_schema_type, _data) do
    {:error, :invalid_arguments}
  end

  defp format_validation_errors(errors) when is_list(errors) do
    Enum.map(errors, fn
      {message, path} when is_binary(message) and is_binary(path) ->
        %{
          message: message,
          path: path
        }

      {message, path} ->
        %{
          message: to_string(message),
          path: to_string(path)
        }

      error ->
        %{
          message: inspect(error),
          path: "#"
        }
    end)
  end

  @doc """
  Encodes an Elixir map to JSON string.

  ## Examples

      iex> data = %{name: "John", status: :active, age: 30}
      iex> ExTypeSchema.Registry.encode(data)
      {:ok, "{\"name\":\"John\",\"status\":\"active\",\"age\":30}"}
  """
  def encode(data) do
    Jason.encode(data)
  end

  @doc """
  Decodes a JSON string to an Elixir map and deserializes based on schema.
  Converts JSON types back to Elixir-specific types (atoms, etc.).

  ## Examples

      iex> json = "{\"name\":\"John\",\"status\":\"active\",\"age\":30}"
      iex> ExTypeSchema.Registry.decode("user", json)
      {:ok, %{name: "John", status: :active, age: 30}}
  """
  def decode(schema_type, json_string) when is_binary(schema_type) and is_binary(json_string) do
    with {:ok, data} <- Jason.decode(json_string),
         {:ok, deserialized} <- deserialize(schema_type, data) do
      {:ok, deserialized}
    end
  end

  @doc """
  Deserializes a map based on schema type.
  Converts string values back to atoms where the schema specifies "atom" type.

  ## Examples

      iex> data = %{"name" => "John", "status" => "active", "age" => 30}
      iex> ExTypeSchema.Registry.deserialize("user", data)
      {:ok, %{name: "John", status: :active, age: 30}}
  """
  def deserialize(schema_type, data) when is_binary(schema_type) and is_map(data) do
    case get_raw_schema(schema_type) do
      {:ok, raw_schema} ->
        {:ok, do_deserialize(data, raw_schema)}

      {:error, :not_found} ->
        {:error, "Schema type '#{schema_type}' not found in registry"}
    end
  end

  defp do_deserialize(data, %{"properties" => properties})
       when is_map(data) and is_map(properties) do
    data
    |> Enum.map(fn {key, value} ->
      prop_key = to_string(key)
      prop_schema = Map.get(properties, prop_key)

      # Convert to atom key if possible
      atom_key =
        try do
          String.to_existing_atom(prop_key)
        rescue
          ArgumentError -> prop_key
        end

      {atom_key, deserialize_value(value, prop_schema)}
    end)
    |> Enum.into(%{})
  end

  defp do_deserialize(data, _schema), do: data

  defp deserialize_value(value, %{"type" => "atom"}) when is_binary(value) do
    try do
      String.to_existing_atom(value)
    rescue
      ArgumentError -> String.to_atom(value)
    end
  end

  defp deserialize_value(value, %{"type" => "object", "object_type" => object_type})
       when is_map(value) do
    case get_raw_schema(object_type) do
      {:ok, nested_schema} ->
        do_deserialize(value, nested_schema)

      {:error, _} ->
        value
    end
  end

  defp deserialize_value(value, %{"type" => "array", "items" => item_schema})
       when is_list(value) do
    Enum.map(value, fn item -> deserialize_value(item, item_schema) end)
  end

  defp deserialize_value(value, %{"format" => "date-time"}) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _offset} -> dt
      _ -> value
    end
  end

  defp deserialize_value(value, %{"format" => "date"}) when is_binary(value) do
    case Date.from_iso8601(value) do
      {:ok, d} -> d
      _ -> value
    end
  end

  defp deserialize_value(value, _), do: value
end
