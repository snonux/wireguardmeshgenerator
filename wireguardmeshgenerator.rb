#!/usr/bin/env ruby

require 'English'
require 'fileutils'
require 'net/scp'
require 'net/ssh'
require 'yaml'
require 'optparse'

# Generates Wireguard keys and configuration files for a specified host.
class KeyTool
  def initialize(myself)
    raise 'Wireguard tool not found' unless system('which wg > /dev/null 2>&1')

    # Initialize keys directory based on the host
    keys_dir = "keys/#{myself}/"
    FileUtils.mkdir_p(keys_dir) unless Dir.exist?(keys_dir)

    @pubkey_path = "#{keys_dir}/pubkey"
    @privkey_path = "#{keys_dir}/privkey"
    @preshared_path = "#{keys_dir}/preshared"

    # Generate keys if any key files are missing
    generate! if !File.exist?(@pubkey_path) ||
                 !File.exist?(@privkey_path) ||
                 !File.exist?(@preshared_path)
  end

  def pub = File.read(@pubkey_path).strip
  def priv = File.read(@privkey_path).strip
  def preshared = File.read(@preshared_path).strip

  private

  # Triggers key generation steps
  def generate! = gen_privpub! && genpsk!
  # Generates the pre-shared key
  def genpsk! = File.write(@preshared_path, `wg genpsk`)

  # Generates private and public key pairs
  def gen_privpub!
    privkey = IO.popen('wg genkey', 'r+', &:read) # Generate private key
    IO.popen('wg pubkey', 'r+') do |io| # Generate public key from private key
      io.puts(privkey)
      io.close_write
      File.write(@privkey_path, privkey) # Save private key to file
      File.write(@pubkey_path, io.read) # Save public key to file
    end
  end
end

# PeerSnippet struct representing Wireguard peer details
PeerSnippet = Struct.new(:myself, :domain, :allowed_ips, :endpoint) do
  # Generates a peer configuration snippet for Wireguard
  def to_s
    keytool = KeyTool.new(myself)

    <<~PEER_CONFIG
      [Peer]
      # #{myself}.#{domain}
      PublicKey = #{keytool.pub}
      PresharedKey = #{keytool.preshared}
      Endpoint = #{endpoint}:56709
      AllowedIPs = #{allowed_ips}/32
    PEER_CONFIG
  end
end

# WireguardConfig struct representing a Wireguard configuration
WireguardConfig = Struct.new(:myself, :hosts) do
  # Generates the full Wireguard configuration
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

  # Cleans up the keys directory for the current host
  def clean!
    %w[dist keys].select { |dir| Dir.exist?(dir) }.each do |dir|
      FileUtils.rm_r(dir)
    end
  end

  # Generates the Wireguard configuration and saves it to a file
  def generate!
    dist_dir = "dist/#{myself}/etc/wireguard"
    FileUtils.mkdir_p(dist_dir) unless Dir.exist?(dist_dir)
    File.write("#{dist_dir}/wg0.conf", to_s)
  end

  private

  # Builds peer snippets for all hosts except the current one
  def peers
    hosts.reject { _1 == myself }.map do |hostname, data|
      PeerSnippet.new(hostname,
                      data['wg0']['domain'],
                      data['wg0']['ip'],
                      data['lan']['ip'])
    end
  end
end

# This is responsible for handling the installation process of the wireguard configuration.
InstallConfig = Struct.new(:myself, :hosts) do
  def initialize(myself, hosts)
    @ssh_user = hosts[myself]['ssh']['user']
    @sudo_cmd = hosts[myself]['ssh']['sudo_cmd']
    @restart_cmd = hosts[myself]['ssh']['restart_cmd']
  end

  # Uploads the configuration file to a remote host
  def upload!
    wg0_conf = "dist/#{myself}/etc/wireguard/wg0.conf"
    puts "Uploading #{wg0_conf} to #{myself}:."
    raise "Upload to #{myself} failed" unless Net::SCP.upload!(myself, @ssh_user, wg0_conf, '.')

    self
  end

  # Installs the Wireguard configuration on the remote host
  def install!
    puts "Installing Wireguard config on #{myself}"

    ssh <<~SH
      if [ ! -d #{@config_path} ]; then
        #{@sudo_cmd} mkdir -p #{@config_path}
        #{@sudo_cmd} mv -v wg0.conf #{@config_path}
        #{@sudo_cmd} #{@restart_cmd}
      fi
    SH

    raise "Unable to install Wireguard config on #{myself}" unless $CHILD_STATUS.success?

    self
  end

  def reload!
    puts "Reloading Wireguard config on #{myself}"

    ssh <<~SH
      #{@sudo_cmd} #{@restart_cmd}
    SH

    raise "Unable to reload Wireguard config on #{myself}" unless $CHILD_STATUS.success?

    self
  end

  private

  def ssh(command)
    Net::SSH.start(myself, @ssh_user) do |ssh|
      ssh.exec!(command)
    end
  end
end

begin
  CONFIG = YAML.load_file('wireguardmeshgenerator.yaml').freeze
  options = {}
  OptionParser.new do |opts|
    opts.on('--generate', 'Generate Wireguard configs') { options[:generate] = true }
    opts.on('--install', 'Install Wireguard configs') { options[:install] = true }
    opts.on('--clean', 'Clean Wireguard configs') { options[:clean] = true }
  end.parse!

  if options[:generate]
    CONFIG['hosts'].each_key do |hostname|
      WireguardConfig.new(hostname, CONFIG['hosts']).generate!
    end
  end

  if options[:install]
    CONFIG['hosts'].each_key do |hostname|
      InstallConfig.new(hostname, CONFIG['hosts']).upload!.install!.reload!
    end
  end

  if options[:clean]
    CONFIG['hosts'].each_key do |hostname|
      WireguardConfig.new(hostname, CONFIG['hosts']).clean!
    end
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 2
end
