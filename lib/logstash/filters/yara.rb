# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'time'
require 'aerospike'
require 'text'
require 'yaml'

require_relative "util/yara_constant"
require_relative "util/aerospike_config"
require_relative "util/aerospike_manager"

class LogStash::Filters::Yara < LogStash::Filters::Base
  include YaraConstant
  include Aerospike

  config_name "yara"

  # Python path
  config :python,                   :validate => :string,         :default => "/usr/bin/python2.6"
  # File that is going to be analyzed
  config :file,                     :validate => :string,         :default => "[path]"
  # Where you want the score to be placed
  config :score_name,               :validate => :string,         :default => "fb_yara"
  # Where you want the latency to be placed
  config :latency_name,             :validate => :string,         :default => "yara_latency"
  # Where you want the data to be placed
  config :target,                   :validate => :string,         :default => "yara"
  # Pyyara python script path
  config :script,                   :validate => :string,         :default => "/opt/rb/var/yara/scripts/pyyara.py"
  # Path of yara - Test
  #config :dir,                      :validate => :string,         :default => "/opt/rb/var/yara"
  # Path of yara_weights
  config :yara_weights,             :validate => :string,         :default => "/opt/rb/var/yara/yara_loader.yml"
  # Aerospike server in the form "host:port"
  config :aerospike_server,         :validate => :string,         :default => ""
  # Namespace is a Database name in Aerospike
  config :aerospike_namespace,      :validate => :string,         :default => "malware"


  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    begin
      @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
      @aerospike_server = @aerospike_server[0] if @aerospike_server.class.to_s == "Array"
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))

    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end # def register

  private

  def get_yara_info

    yara_score = -1
    det_rules = []
    yara_json={}

    unless File.exist?(@path)
      @logger.error("File #{@path} does not exist.")
      return [yara_json, yara_score]
    end

    unless File.exist?(@script)
      @logger.error("Script Yara - pyyara.py - is not in #{@script}.")
      return [yara_json, yara_score]
    end

    unless File.exist?(@dir)
      @logger.error("Path #{@dir} does not exist.")
      return [yara_json, yara_score]
    end

    unless File.exist?(@yara_weights)
      @logger.error("File #{@yara_weights} does not exist.")
      return [yara_json, yara_score]
    end

    unless File.exist?(@python)
      @logger.error("Python is not in #{@python}.")
      return [yara_json, yara_score]
    end

    begin
      yara_json = JSON.parse(`#{@python} #{@script} #{@file}`)
    rescue JSON::ParseError
      @logger.error("Cannot get score from #{@file}")
    end



    yara_result = `#{@yara_bin} -w #{@yara_rule} #{@path}`

    det_rules = yara_result.split("\n").map! { |rule| rule.split(" ").first } if !yara_result.empty?
    yara_json = {
      "detected_rules" => det_rules
    }
    yara_score = (det_rules.length * @weight).round

    [yara_json, yara_score]
  end

  public

  def filter(event)

    @path = event.get(@file)

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yara_info,yara_score = get_yara_info

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target,yara_info)
    event.set(@score_name,yara_score)

    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Yara
