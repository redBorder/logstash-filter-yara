require "yaml"
require 'aerospike'

module AerospikeManager

  WEIGHTS_CONFIG_FILE = "/opt/rb/var/rb-sequence-oozie/conf/weights.yml" unless defined? WEIGHTS_CONFIG_FILE

  include Aerospike

  def self.update_malware_hash_score(aerospike, namespace, set, hash, loader_score_name, loader_score, loader_type)

    self.set_record(aerospike, Bin.new(loader_score_name, loader_score), namespace, set, hash)

    record = get_record(aerospike, namespace, set, hash)
    section_score_name = "g_" + loader_type + "_score"
    global_score_name = "score"

    list_type = self.get_list_type(aerospike, namespace, set, hash)

    global_score = 0.0
    section_score = 0.0
    bins = []

    if record != nil
      scores = record.bins

      # Compute section score.
      scores.each do | entry_key, entry_value |
        if entry_key.start_with? loader_type and !entry_key.include? "score"
          local_score = entry_value.to_f
          weight = YAML.load_file(WEIGHTS_CONFIG_FILE)["hash"][entry_key]

          if local_score > 0
            section_score += local_score * weight
          end
        end
        bins.push(Bin.new(section_score_name, section_score.round))
      end

      # Compute global score.
      case list_type
      when "black"
        @logger.info("Hash " + hash + " is blacklisted")
        global_score = 100
      when "white"
        @logger.info("Hash " + hash + " is whitelisted")
        global_score = 0

      else
        scores.each do | entry_key, entry_value |
          if entry_key.start_with? "g_"
            local_score = entry_value.to_f
            weight = YAML.load_file(WEIGHTS_CONFIG_FILE)["hash"][entry_key]

            if local_score > 0
              global_score += local_score * weight
            end
          end
        end
      end
    end
    bins.push(Bin.new(global_score_name, global_score.round))
    self.set_record(aerospike, bins, namespace, set, hash, 0)
  end

  def self.get_list_type(aerospike, namespace, set, hash)
    begin
      list_type = ''
      key = Key.new(namespace,set,hash)
      record = aerospike.get(key,[],Policy.new)
      record.bins.each do |entry_key, entry_value|
        if entry_key == "list_type"
          list_type = entry_value
          break
        end
      end
      list_type
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end

  def self.get_records(aerospike,namespace,set)
    records = []
    begin
      stmt = Statement.new(namespace, set)
      records = aerospike.query(stmt)
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error("Failed when trying to get records.")
      @logger.error(ex.message)
    end
    records
  end

  def self.get_record(aerospike, namespace, set, hash)
    get_records(aerospike, namespace, set).each do |record|
      key = record.key.user_key
      return record if key == hash
    end
    return nil
  end

  def self.get_value(aerospike, namespace, set, hash, field)
    begin
      record = get_record(aerospike, namespace, set, hash)
      unless record.nil?
        record.bins.each do |entry_key, entry_value|
          return entry_value if entry_key == field
        end
      end
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
    return nil
  end

  def self.set_record(aerospike, bins, namespace, set, hash, ttl = 0)
    begin
      key = Key.new(namespace,set,hash)

      policy = WritePolicy.new
      policy.expiration = ttl

      aerospike.put(key,bins,policy)
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end
end
