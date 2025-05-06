#!/usr/bin/env ruby
# This script is a Wireguard mesh configuration generator and manager.
# It provides options to generate, install, and clean Wireguard configurations
# for a set of hosts specified in a YAML configuration file.

require 'English'
require 'fileutils'
require 'net/scp'
require 'net/ssh'
require 'yaml'

require 'optparse'

# KeyTool is a utility class for managing WireGuard keys.
# It ensures the presence of required directories and files for public/private keys
# and preshared keys (PSKs). If keys are missing, it generates them using the `wg` tool.
class KeyTool
  # Initializes the KeyTool instance.
  # Ensures the `wg` tool is available and required directories exist.
  # Generates public/private keys if they are missing.
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

  # Retrieves or generates a preshared key (PSK) for communication with a peer.
  def psk(peer)
    psk_path = "#{@psk_dir}/#{[@myself, peer].sort.join('_')}.key"
    gen_psk!(psk_path) unless File.exist?(psk_path)
    File.read(psk_path).strip
  end

  private

  # Generates a preshared key (PSK) and writes it to the specified path.
  def gen_psk!(psk_path) = File.write(psk_path, `wg genpsk`)

  # Generates a private key and its corresponding public key.
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

# PeerSnippet is a Struct that represents the configuration for a WireGuard peer.
PeerSnippet = Struct.new(:myself, :peer, :domain, :wgdomain,
                         :allowed_ips, :endpoint, :keepalive) do
  # Converts the PeerSnippet instance into a WireGuard peer configuration string.
  # This includes the public key, preshared key, allowed IPs, endpoint, and
  # keepalive settings.
  def to_s
    keytool = KeyTool.new(myself)
    <<~PEER_CONF
      [Peer]
      # #{myself}.#{domain} as #{myself}.#{wgdomain}
      PublicKey = #{keytool.pub}
      PresharedKey = #{keytool.psk(peer)}
      AllowedIPs = #{allowed_ips}/32
      #{endpoint_str}
      #{keepalive_str}
    PEER_CONF
  end

  # Generates the endpoint configuration string for the peer.
  # If the peer is behind NAT, a comment is returned instead.
  def endpoint_str
    return '# Due to NAT no Endpoint configured' if endpoint == :behind_nat

    "Endpoint = #{endpoint}:56709"
  end

  # Generates the PersistentKeepalive configuration string for the peer.
  # If keepalive is not enabled, a comment is returned instead.
  def keepalive_str
    return '# No KeepAlive configured' unless keepalive

    'PersistentKeepalive = 25'
  end
end

# WireguardConfig is a configuration generator for WireGuard mesh networks.
# It generates configuration files for WireGuard interfaces and peers.
WireguardConfig = Struct.new(:myself, :hosts) do
  def to_s
    keytool = KeyTool.new(myself)
    <<~CONF
      [Interface]
      # #{myself}.#{hosts[myself]['wg0']['domain']}
      #{address}
      PrivateKey = #{keytool.priv}
      ListenPort = 56709

      #{peers(&:to_s).join("\n")}
    CONF
  end

  # Cleans up generated directories and files.
  # Removes the `dist` and `keys` directories if they exist.
  def clean!
    %w[dist keys].select { |dir| Dir.exist?(dir) }.each do |dir|
      FileUtils.rm_r(dir)
    end
  end

  # Generates the WireGuard configuration file for the current host.
  # Creates the necessary directory structure and writes the configuration
  # to `wg0.conf`.
  def generate!
    dist_dir = "dist/#{myself}/etc/wireguard"
    puts "Generating #{dist_dir}/wg0.conf"
    FileUtils.mkdir_p(dist_dir) unless Dir.exist?(dist_dir)
    File.write("#{dist_dir}/wg0.conf", to_s)
  end

  private

  # Generates the address configuration for the current host.
  # For OpenBSD, it returns a placeholder comment. Otherwise, it returns the
  # IP address as that option isn't supported on OpenBSD.
  def address
    return '# No Address = ... for OpenBSD here' if hosts[myself]['os'] == 'OpenBSD'

    "Address = #{hosts[myself]['wg0']['ip']}"
  end

  # Generates a list of peer configurations for the WireGuard mesh network.
  # Excludes peers specified in the `exclude_peers` list and the current host itself.
  # Determines the appropriate endpoint and keepalive settings for each peer.
  def peers
    exclude = hosts[myself].fetch('exclude_peers', []).append(myself)
    # Check if the current host is in the local area network (LAN).
    in_lan = hosts[myself].key?('lan')
    hosts.reject { exclude.include?(_1) }.map do |peer, data|
      # Determine if the peer is in the LAN.
      peer_in_lan = data.key?('lan')
      reach = data[peer_in_lan ? 'lan' : 'internet']
      endpoint = peer_in_lan == in_lan || !peer_in_lan ? reach['ip'] : :behind_nat
      # Determine if keepalive is needed (only for LAN-to-internet connections).
      keepalive = in_lan && !peer_in_lan
      PeerSnippet.new(peer, myself, reach['domain'], data['wg0']['domain'],
                      data['wg0']['ip'], endpoint, keepalive)
    end
  end
end

# InstallConfig is a utility class for managing the installation,
# configuration, and restarting of Wireguard on a remote host. It uses SSH and
# SCP for remote operations.
InstallConfig = Struct.new(:myself, :hosts) do
  def initialize(myself, hosts)
    @myself = myself

    data = hosts[myself]
    domain = data.dig('lan', 'domain') || data.dig('internet', 'domain')
    @fqdn = "#{myself}.#{domain}"
    @ssh_user = data['ssh']['user']
    @sudo_cmd = data['ssh']['sudo_cmd']
    @reload_cmd = data['ssh']['reload_cmd']
    @conf_dir = data['ssh']['conf_dir']
  end

  # Uploads the Wireguard configuration file to the remote host.
  def upload!
    wg0_conf = "dist/#{@myself}/etc/wireguard/wg0.conf"
    scp(wg0_conf)
    self
  end

  # Installs the Wireguard configuration file on the remote host.
  # Ensures the configuration directory exists and has the correct permissions.
  def install!
    puts "Installing Wireguard config on #{@myself}"
    ssh <<~SH
      if [ ! -d #{@conf_dir} ]; then
        #{@sudo_cmd} mkdir -p #{@conf_dir}
      fi
      #{@sudo_cmd} chmod 700 #{@conf_dir}
      #{@sudo_cmd} mv -v wg0.conf #{@conf_dir}
      #{@sudo_cmd} chmod 644 #{@conf_dir}/wg0.conf
    SH
  end

  # Reloads the Wireguard service on the remote host and displays its status.
  def reload!
    puts "Reloading Wireguard on #{@myself}"
    ssh <<~SH
      #{@sudo_cmd} #{@reload_cmd}
      #{@sudo_cmd} wg show
    SH
  end

  private

  # Uploads a file to the remote host using SCP.
  def scp(src, dst = '.')
    puts "Uploading #{src} to #{@fqdn}:#{dst}"
    raise "Upload #{src} to #{@fqdn}:#{dst} failed" unless
      Net::SCP.upload!(@fqdn, @ssh_user, src, dst)
  end

  # Executes a shell command on the remote host using SSH.
  def ssh(cmd)
    File.delete('cmd.sh') if File.exist?('cmd.sh')
    File.write('cmd.sh', <<~SH) and scp('cmd.sh')
      #!/bin/sh
      set -x
      #{cmd}
      rm $0
    SH
    Net::SSH.start(@fqdn, @ssh_user) do |ssh|
      output = ssh.exec!('sh cmd.sh')
      raise output unless output.exitstatus.zero?

      puts output
    end
    self
  end
end

begin
  options = { hosts: [] }
  OptionParser.new do |opts|
    opts.banner = 'Usage: wireguardmeshgenerator.rb [options]'
    opts.on('--generate', 'Generate Wireguard configs') do
      options[:generate] = true
    end
    opts.on('--install', 'Install Wireguard configs') do
      options[:install] = true
    end
    opts.on('--clean', 'Clean Wireguard configs') do
      options[:clean] = true
    end
    opts.on('--hosts=HOSTS', 'Comma separated hosts to configure') do |hosts|
      options[:hosts] = hosts.split(',')
    end
  end.parse!

  conf = YAML.load_file('wireguardmeshgenerator.yaml').freeze

  conf['hosts'].keys.select { options[:hosts].empty? || options[:hosts].include?(_1) }
               .each do |host|
    # Generate Wireguard configuration for the hostreload!
    WireguardConfig.new(host, conf['hosts']).generate! if options[:generate]
    # Install Wireguard configuration for the host.
    InstallConfig.new(host, conf['hosts']).upload!.install!.reload! if options[:install]
    # Clean Wireguard configuration for the host.
    WireguardConfig.new(host, conf['hosts']).clean! if options[:clean]
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 2
end
