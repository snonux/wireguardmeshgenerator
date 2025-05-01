#!/usr/bin/env ruby

require 'English'
require 'fileutils'
require 'net/scp'
require 'net/ssh'
require 'yaml'

require 'optparse'

class KeyTool
  def initialize(myself)
    raise 'Wireguard tool not found' unless system('which wg > /dev/null 2>&1')

    @myself = myself
    @psk_dir = 'keys/psk'
    mykeys_dir = "keys/#{myself}"

    [mykeys_dir, @psk_dir].each do |dir|
      FileUtils.mkdir_p(dir) unless Dir.exist?(dir)
    end

    @pubkey_path = "#{mykeys_dir}/pub.key"
    @privkey_path = "#{mykeys_dir}/priv.key"

    gen_privpub! if !File.exist?(@pubkey_path) || !File.exist?(@privkey_path)
  end

  def pub = File.read(@pubkey_path).strip
  def priv = File.read(@privkey_path).strip

  # Preshared key
  def psk(peer)
    psk_path = "#{@psk_dir}/#{[@myself, peer].sort.join('_')}.key"
    gen_psk!(psk_path) unless File.exist?(psk_path)
    File.read(psk_path).strip
  end

  private

  def gen_psk!(psk_path) = File.write(psk_path, `wg genpsk`)

  def gen_privpub!
    privkey = IO.popen('wg genkey', 'r+', &:read)
    IO.popen('wg pubkey', 'r+') do |io|
      io.puts(privkey)
      io.close_write
      File.write(@privkey_path, privkey)
      File.write(@pubkey_path, io.read)
    end
  end
end

PeerSnippet = Struct.new(:myself, :peer, :domain, :wgdomain,
                         :allowed_ips, :endpoint) do
  def to_s
    keytool = KeyTool.new(myself)
    <<~PEER_CONFIG
      [Peer]
      # #{myself}.#{domain} as #{myself}.#{wgdomain}
      PublicKey = #{keytool.pub}
      pskKey = #{keytool.psk(peer)}
      Endpoint = #{endpoint}:56709
      AllowedIPs = #{allowed_ips}/32
    PEER_CONFIG
  end
end

WireguardConfig = Struct.new(:myself, :hosts) do
  def to_s
    keytool = KeyTool.new(myself)
    <<~CONFIG
      [Interface]
      # #{myself}.#{hosts[myself]['wg0']['domain']}
      Address = #{hosts[myself]['wg0']['ip']}
      PrivateKey = #{keytool.priv}
      ListenPort = 56709

      #{peers(&:to_s).join("\n")}
    CONFIG
  end

  def clean!
    %w[dist keys].select { |dir| Dir.exist?(dir) }.each do |dir|
      FileUtils.rm_r(dir)
    end
  end

  def generate!
    dist_dir = "dist/#{myself}/etc/wireguard"
    FileUtils.mkdir_p(dist_dir) unless Dir.exist?(dist_dir)
    File.write("#{dist_dir}/wg0.conf", to_s)
  end

  private

  def peers
    hosts.reject { _1 == myself }.map do |hostname, data|
      PeerSnippet.new(hostname, myself,
                      data['lan']['domain'],
                      data['wg0']['domain'],
                      data['wg0']['ip'],
                      data['lan']['ip'])
    end
  end
end

InstallConfig = Struct.new(:myself, :hosts) do
  def initialize(myself, hosts)
    @ssh_user = hosts[myself]['ssh']['user']
    @sudo_cmd = hosts[myself]['ssh']['sudo_cmd']
    @restart_cmd = hosts[myself]['ssh']['restart_cmd']
  end

  def upload!
    wg0_conf = "dist/#{myself}/etc/wireguard/wg0.conf"
    puts "Uploading #{wg0_conf} to #{myself}:."
    raise "Upload to #{myself} failed" unless
      Net::SCP.upload!(myself, @ssh_user, wg0_conf, '.')

    self
  end

  def install!
    puts "Installing Wireguard config on #{myself}"
    ssh <<~SH
      if [ ! -d #{@config_path} ]; then
        #{@sudo_cmd} mkdir -p #{@config_path}
        #{@sudo_cmd} mv -v wg0.conf #{@config_path}
      fi
    SH
    raise "Unable to install Wireguard config on #{myself}" unless
      $CHILD_STATUS.success?

    self
  end

  def restart!
    puts "Restarting Wireguard on #{myself}"
    ssh "#{@sudo_cmd} #{@restart_cmd}"
    raise "Unable to restart Wireguard on #{myself}" unless
       $CHILD_STATUS.success?
  end

  private

  def ssh(cmd) = Net::SSH.start(myself, @ssh_user) { _1.exec!(cmd) }
end

begin
  options = {}
  OptionParser.new do |opts|
    opts.on('--generate', 'Generate Wireguard configs') do
      options[:generate] = true
    end
    opts.on('--install', 'Install Wireguard configs') do
      options[:install] = true
    end
    opts.on('--clean', 'Clean Wireguard configs') do
      options[:clean] = true
    end
  end.parse!

  conf = YAML.load_file('wireguardmeshgenerator.yaml').freeze
  conf['hosts'].each_key do |hostname|
    WireguardConfig.new(hostname, conf['hosts']).generate! if
      options[:generate]

    InstallConfig.new(hostname, conf['hosts']).upload!.install!.restart! if
      options[:install]

    WireguardConfig.new(hostname, conf['hosts']).clean! if
      options[:clean]
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 2
end
