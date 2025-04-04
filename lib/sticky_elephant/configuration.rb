module StickyElephant
  class Configuration
    attr_reader :log_path, :log_level, :port, :host, :abort_on_exception,
      :hpf_host, :hpf_port, :hpf_ident, :hpf_secret, :use_hpf, :debug
    alias_method :debug?, :debug
    # alias_method :use_hpf?, :use_hpf
    # alias_method :use_hpfeeds, :use_hpf
    # alias_method :use_hpfeeds?, :use_hpf


    # from_cli: log_path: "./sticky_elephant.log",
    #              port: 5432, host: '0.0.0.0',
    #              log_level: Logger::INFO,
    #              abort_on_exception: false
    def initialize(configuration_path = "./sticky_elephant.conf")
      conf                = YAML.load_file(configuration_path)
      @port               = conf.fetch(:port, 5432)
      @host               = conf.fetch(:host, '0.0.0.0')
      @debug              = conf.fetch(:debug, false)
      @log_path           = conf.fetch(:log_path, './logs/sticky_elephant.log')
      @abort_on_exception = conf.fetch(:abort_on_exception, false)
      # @hpf_host           = conf.fetch(:hpf_host, nil)
      # @hpf_port           = conf.fetch(:hpf_port, 10_000)
      # @hpf_ident          = conf.fetch(:hpf_ident, nil)
      # @hpf_secret         = conf.fetch(:hpf_secret, nil)
      # @use_hpf            = conf.fetch(:use_hpf, false)
      # check_hpf_configuration! if use_hpf?
      ensure_log_directory_exists!
    end

    def log_level
      debug? ? Logger::DEBUG : Logger::INFO
    end

    private
    def ensure_log_directory_exists!
      log_dir = File.dirname(@log_path)

      unless Dir.exist?(log_dir)
        puts "Creating log directory: #{log_dir}"
        FileUtils.mkdir_p(log_dir) # Creates the folder if it doesn’t exist
      end
    end
    #
    # def check_hpf_configuration!
    #   error_messages = []
    #   (error_messages << "Invalid HPF host") if hpf_host.nil? || hpf_host.empty?
    #   (error_messages << "Invalid HPF ident") if hpf_ident.nil? || hpf_ident.empty?
    #   (error_messages << "Invalid HPF secret") if hpf_secret.nil? || hpf_secret.empty?
    #   abort(error_messages.join(", ")) unless error_messages.empty?
    # end

  end
end
