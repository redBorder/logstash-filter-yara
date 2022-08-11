# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'json'
require 'time'

require_relative "util/yara_constant"

class LogStash::Filters::Yara < LogStash::Filters::Base
  include YaraConstant

  config_name "yara"

  config :yara_rule,    :validate => :string,   :default => "/opt/rb/var/yara_rules/rules.yara"
  config :yara_bin,    :validate => :string,   :default => "/opt/rb/bin/yara"
  config :file,         :validate => :string,   :default => "[path]"
  config :score_name,   :validate => :string,   :default => "fb_yara"
  config :weight,       :default => 1.0
  config :latency_name, :validate => :string,   :default => "yara_latency"
  config :target,       :validate => :string,   :default => "yara"

  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables

  end # def register

  private

  def get_yara_info

    yara_score = -1
    det_rules = []
    yara_json={}

    unless File.exist?(@yara_bin)
      @logger.error("Yara binary is not in #{@yara_bin}.")
      return [yara_json, yara_score]
    end

    unless File.exist?(@path)
      @logger.error("File #{@path} does not exist.")
      return [yara_json, yara_score]
    end

    unless File.exist?(@yara_rule)
      @logger.error("Yara rule is not in #{@yara_rule}.")
      return [yara_json, yara_score]
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
