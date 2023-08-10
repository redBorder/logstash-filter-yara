# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'time'
require 'text'
require 'yaml'

require_relative "util/yara_constant"

class LogStash::Filters::Yara < LogStash::Filters::Base
  include YaraConstant

  config_name "yara"

  # Python path
  config :python,                     :validate => :string,         :default => "/usr/bin/python2.6"
  # File that is going to be analyzed
  config :file_field,                 :validate => :string,         :default => "[path]"
  # Where you want the score to be placed
  config :score_name,                 :validate => :string,         :default => "fb_yara"
  # Where you want the latency to be placed
  config :latency_name,               :validate => :string,         :default => "yara_latency"
  # Where you want the data to be placed
  config :target,                     :validate => :string,         :default => "yara"
  # Pyyara python script path
  config :pyyara_py,                  :validate => :string,         :default => "/opt/rb/var/rb-sequence-oozie/workflow/lib/scripts/pyyara.py"
  # Path of yara_weights
  config :yara_weights,               :validate => :string,         :default => "/opt/rb/var/rb-sequence-oozie/workflow/yara_loader.yml"
  # path of yara rules
  config :path_yara_rules,            :validate => :string,         :default => "/usr/share/logstash/yara_rules/"
  # file of yara rules
  config :file_yara_rules,            :validate => :string,         :default => "/usr/share/logstash/yara_rules/rules.yara"
  # path of weights
  config :weights,                    :validate => :string,         :default => "/opt/rb/var/rb-sequence-oozie/conf/weights.yml"


  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables

  end # def register

  private

  def get_yara_info

    final_score = -1
    yara_info = {}


    unless File.exist?(@pyyara_py)
      @logger.error("Script Yara - pyyara.py - is not in #{@pyyara_py}.")
      return [yara_info, final_score]
    end

    unless File.exist?(@yara_weights)
      @logger.error("The file #{@yara_weights} does not exist.")
      return [yara_info, final_score]
    end

    unless File.exist?(@python)
      @logger.error("Python is not in #{@python}.")
      return [yara_info, final_score]
    end

    unless File.exist?(@path_yara_rules)
      @logger.error("Directory #{@path_yara_rules} does not exist.")
      return [yara_info, final_score]
    end

    unless File.exist?(@file_yara_rules)
      @logger.error("The file #{@file_yara_rules} does not exist.")
      return [yara_info, final_score]
    end

    
    hits={}
    scores={}

    high_severity = "high"
    medium_severity = "medium"
    low_severity = "low"

    severities = [high_severity, medium_severity, low_severity]

    severities.each do |severity|
      hits[severity] = 0
      scores[severity] = 0
    end

    matches = []
    yara_exec_error = false
    
    begin
      command = `#{@pyyara_py} #{@file_path} #{@path_yara_rules}`
      py_json = JSON.parse(command)
      matches = py_json["matches"]
    rescue
      yara_exec_error = true
      @logger.error "Yara encountered an error while calculating matches for this file, please review your rules and try again!"
    end

    rules = []

    matches.each do |n|

      meta = n["meta"]
      severity = meta["severity"]
      rule = n["rule"]
      rules<<rule


      if severity.nil?
        hits[low_severity] += 1
        next
      end

      case severity.downcase
      when high_severity.downcase
        hits[severity] += 1
      when medium_severity.downcase
        hits[severity] += 1
      when low_severity.downcase
        hits[severity] += 1
      end
    end

    yara_exec_error == false ? final_score = 0.0 : final_score = -1

    sev = YAML.load_file("#{@yara_weights}")


    if (!(hits[high_severity] == 0 and hits[medium_severity] == 0 and hits[low_severity] == 0))

      severities.each do |severity|
        if hits[severity] > sev[severity]["high_lower_threshold"]
          scores[severity] = sev[severity]["high_score"]
        elsif (hits[severity] < sev[severity]["low_upper_threshold"] and hits[severity] > 0)
          scores[severity] = sev[severity]["low_score"]
        elsif hits[severity] > 0
          scores[severity] = sev[severity]["medium_score"]
        end
      end
    end

    severities.each do |severity|
      weighing = sev["general"][severity]
      score = scores[severity]
      final_score += weighing * score
    end

    w = YAML.load_file("#{@weights}")
    weight_yara = w["hash"]["fb_yara"]

    yara_json = {
      "Hits" => hits,
      "yara_rules" => matches,
      "Weight" => weight_yara
    }

    [yara_json, final_score.round]
  end

  public

  def filter(event)

    @file_path = event.get(@file_field)
    @logger.info("[#{@target}] processing #{@file_path}")

    @hash = event.get('sha256')

    if @hash.nil?
      begin
        @hash = Digest::SHA2.new(256).hexdigest File.read @file_path
        event.set('sha256', @hash)
      rescue Errno::ENOENT => ex
        @logger.error(ex.message)
      end
    end

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yara_result,final_score = get_yara_info

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    timestamp = Time.now.to_i
    event.set("timestamp",timestamp)

    event.set(@latency_name, elapsed_time)
    event.set(@target,yara_result)
    event.set("loader",@target)
    event.set(@score_name,final_score)


    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Yara
