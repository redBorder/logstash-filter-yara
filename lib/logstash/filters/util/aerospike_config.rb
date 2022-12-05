require "yaml"

module AerospikeConfig

  AEROSPIKE_CONFIG_FILE="/opt/rb/var/www/rb-rails/config/aerospike.yml" unless defined? AEROSPIKE_CONFIG_FILE

  def self.servers
    servers = []
    if File.exist?(AEROSPIKE_CONFIG_FILE)
      production_config = YAML.load_file(AEROSPIKE_CONFIG_FILE)
      servers = production_config["production"]["servers"] || []
    end
    servers = "localhost:3000" if servers.empty?
    return servers
  end

end
