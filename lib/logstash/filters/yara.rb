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
  config :yara_path,    :validate => :string,   :default => "/opt/rb/bin/yara"
  config :file,         :validate => :string,   :default => "[path]"
  #config :target,       :validate => :string,   :default => "yara"
  config :score_name,   :validate => :string,   :default => "fb_yara"
  config :weight,       :default => 100.0
  config :latency_name, :validate => :string,   :default => "yara_latency"


  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables

  end # def register

  public

  def filter(event)

    @path = event.get(@file)

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    det_rules = []
    yara_result = `#{@yara_path} -w #{@yara_rule} #{@path}`

    det_rules = yara_result.split("\n").map! { |rule| rule.split(" ").first } if !yara_result.empty?

    yara_score = (det_rules.length * @weight).round


    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)
    event.set(@latency_name, elapsed_time)
    event.set('detected_rules',det_rules)

    #event.set(@target,)
    event.set(@score_name,yara_score)

    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Yara
