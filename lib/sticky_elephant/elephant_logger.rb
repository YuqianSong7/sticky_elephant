require 'click_house'

ClickHouse.config do |config|
  config.logger = Logger.new(STDOUT)
  config.database = 'metrics'
  config.scheme = 'http'
  config.host = 'localhost'
  config.port = 'port'
  config.username = 'user'
  config.password = 'password'
  config.json_parser = ClickHouse::Middleware::ParseJson
  config.json_serializer = ClickHouse::Serializer::JsonSerializer
  config.ssl_verify = false
  config.symbolize_keys = false
end

module StickyElephant
  class ElephantLogger
    def initialize(configuration)
      @log_path = configuration.log_path
      @text = Logger.new(@log_path, 'daily')
      @text.level = configuration.log_level
    end

    %i(debug info warn error fatal unknown).each do |level|
      define_method(level) do |*args, &block|
        @text.send(level, *args, &block)
      end
    end

    def close
      rotate_and_upload_log if log_rotated?
      text.close
    end

    private

    attr_reader :text

    def log_rotated?
      rotated_log = "#{@log_path}.#{(Date.today - 1).strftime('%Y-%m-%d')}"
      File.exist?(rotated_log)
    rescue StandardError => e
      puts "Error checking log rotation: #{e.message}"
      false
    end

    def rotate_and_upload_log
      rotated_log = "#{@log_path}.#{(Date.today - 1).strftime('%Y-%m-%d')}"
      return unless File.exist?(rotated_log)

      begin
        client = ClickHouse.connection

        if client.ping
          puts "ClickHouse connection successful!"
        else
          puts "ClickHouse connection failed!"
          return
        end

        # Ensure the logs table exists
        create_logs_table_if_not_exists(client)

        # Prepare batch insert array
        log_entries = []
        File.open(rotated_log, 'r') do |file|
          file.each_line do |line|
            parsed_entry = parse_log_line(line)
            log_entries << parsed_entry if parsed_entry
          end
        end

        # Insert logs in batches
        batch_insert_logs(client, log_entries) unless log_entries.empty?
      rescue Errno::ENOENT => e
        puts "Error reading log file: #{e.message}"
      rescue StandardError => e
        puts "Unexpected error in log rotation: #{e.message}"
      end
    end

    def create_logs_table_if_not_exists(client)
      begin
        create_table_sql = <<~SQL
          CREATE TABLE IF NOT EXISTS logs
          (
              level String,
              timestamp DateTime,
              source_ip String,
              action String,
              message String
          )
          ENGINE = MergeTree()
          ORDER BY timestamp;
        SQL

        client.query(create_table_sql)
      rescue StandardError => e
        puts "Error creating ClickHouse table: #{e.message}"
      end
    end
    def parse_log_line(line)
      begin
        # Assuming log format: "level, timestamp, message"
        match = line.match(/^([A-Z]),\s+([\d-]+\s[\d:.]+)\s+([A-Z]+)\s--\s(.+)$/)
        return nil unless match

        level = match[1]  # Log level
        timestamp = DateTime.parse(match[2]).to_time  # Parse timestamp
        message = match[4]  # The rest of the message

        # Extract source_ip and action if available
        source_ip, action = extract_source_ip_and_action(message)

        {
          level: level,
          timestamp: timestamp,
          source_ip: source_ip,
          action: action,
          message: message
        }
      rescue StandardError => e
        puts "Error parsing log line: #{line} - #{e.message}"
        nil
      end
    end

    def extract_source_ip_and_action(message)
      parts = message.split(':', 2) # Split message at first colon
      source_ip = parts[0].strip if parts[0] =~ /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ # Validate IP format
      action = parts[1]&.strip
      [source_ip, action]
    end

    def batch_insert_logs(client, logs)
      begin
        client.insert_rows('logs', logs)
        puts "Inserted #{logs.size} logs into ClickHouse."
      rescue StandardError => e
        puts "Error inserting logs into ClickHouse: #{e.message}"
      end
    end
  end
end

