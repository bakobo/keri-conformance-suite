import Config

# cesrixir logs through Logger, and the adapter protocol reserves standard output for responses.
config :logger, :default_handler, config: [type: :standard_error]
