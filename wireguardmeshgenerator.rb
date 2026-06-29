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
    # Check if allowed_ips already contains CIDR notation or is a special routing rule
    allowed_ips_str = allowed_ips.include?('/') ? allowed_ips : "#{allowed_ips}/32"
    <<~PEER_CONF
      [Peer]
      # #{myself}.#{domain} as #{myself}.#{wgdomain}
      PublicKey = #{keytool.pub}
      PresharedKey = #{keytool.psk(peer)}
      AllowedIPs = #{allowed_ips_str}
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
      #{dns}

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
  # IP address (and optionally IPv6) as that option isn't supported on OpenBSD.
  # Supports dual-stack: if ipv6 field is present, outputs both IPv4 and IPv6 addresses.
  # FreeBSD requires subnet mask on IPv4 address for wg-quick.
  def address
    return '# No Address = ... for OpenBSD here' if hosts[myself]['os'] == 'OpenBSD'

    ipv4 = hosts[myself]['wg0']['ip']
    ipv6 = hosts[myself]['wg0']['ipv6']
    # FreeBSD 15.0+ requires /32 host mask on IPv4 Address lines (not /24);
    # without a prefix, service wireguard start fails with "setting interface
    # address without mask is no longer supported"
    ipv4_with_mask = hosts[myself]['os'] == 'FreeBSD' ? "#{ipv4}/32" : ipv4

    # WireGuard supports multiple Address directives for dual-stack
    if ipv6
      "Address = #{ipv4_with_mask}\nAddress = #{ipv6}/64"
    else
      "Address = #{ipv4_with_mask}"
    end
  end

  # Generates DNS configuration for roaming clients.
  # Roaming clients (no 'lan' or 'internet' sections) get DNS servers configured,
  # unless gateway: false (no default route through VPN).
  # Uses Cloudflare (1.1.1.1) and Google (8.8.8.8) public DNS for reliability.
  def dns
    is_roaming = !hosts[myself].key?('lan') && !hosts[myself].key?('internet')
    use_gateway = hosts[myself].fetch('gateway', true)
    return '# No DNS configured' unless is_roaming && use_gateway

    'DNS = 1.1.1.1, 8.8.8.8'
  end

  # Builds peer entries for the WireGuard mesh. Excludes hosts in exclude_peers and self.
  # Determines endpoint, keepalive, and AllowedIPs per peer based on network topology.
  def peers
    exclude = hosts[myself].fetch('exclude_peers', []).append(myself)
    # Check if the current host is in the local area network (LAN).
    in_lan = hosts[myself].key?('lan')
    # Detect if current host is a roaming client (no lan or internet section).
    # Roaming clients need PersistentKeepalive to all peers to maintain NAT traversal.
    is_roaming = !hosts[myself].key?('lan') && !hosts[myself].key?('internet')
    # Check if this host should use gateways for default route (gateway: false disables this).
    use_gateway = hosts[myself].fetch('gateway', true)
    # Track if we've assigned the primary gateway (for mesh subnet routing via gateway:false).
    primary_gateway_assigned = false

    hosts.reject { exclude.include?(_1) }.map do |peer, data|
      # Check if peer is roaming (no lan or internet section).
      # Roaming peers are always behind NAT and cannot be reached directly.
      peer_is_roaming = !data.key?('lan') && !data.key?('internet')

      if peer_is_roaming
        # Roaming peer is always behind NAT, use wg0 domain for identification
        reach = data['wg0']
        endpoint = :behind_nat
      else
        # Regular peer with lan or internet section
        peer_in_lan = data.key?('lan')
        reach = data[peer_in_lan ? 'lan' : 'internet']
        endpoint = peer_in_lan == in_lan || !peer_in_lan ? reach['ip'] : :behind_nat
      end

      # Set keepalive: LAN hosts connecting to internet hosts, OR roaming clients connecting to anyone.
      keepalive = is_roaming || (in_lan && !peer_in_lan)
      allowed_ips, primary_gateway_assigned = compute_allowed_ips(
        peer, data, is_roaming, use_gateway, primary_gateway_assigned
      )

      PeerSnippet.new(peer, myself, reach['domain'], data['wg0']['domain'],
                      allowed_ips, endpoint, keepalive)
    end
  end

  # Returns additional AllowedIPs to append to a gateway peer's entry on infra hosts.
  # Hosts that declare `reachable_via: <gateway>` are NAT-roaming clients whose
  # return traffic must flow via that gateway back to them. This ensures the gateway
  # peer's AllowedIPs covers the roaming client's wg0 IPs, so infra hosts route
  # traffic destined for those clients through the gateway.
  def extra_ips_via_gateway(gateway_name)
    hosts.filter_map do |_name, data|
      next unless data['reachable_via'] == gateway_name

      ipv4 = data['wg0']['ip']
      ipv6 = data['wg0']['ipv6']
      ipv6 ? "#{ipv4}/32, #{ipv6}/128" : "#{ipv4}/32"
    end
  end

  # Computes AllowedIPs for a peer entry on the current (myself) host.
  # Returns [allowed_ips_string, updated_primary_gateway_assigned].
  # - Roaming clients with gateway:true: all traffic via VPN (0.0.0.0/0, ::/0).
  # - Roaming clients with gateway:false: mesh subnet for primary gateway, specific IPs for others.
  # - Regular mesh peers: their specific IPs; gateway peers also get extra IPs for
  #   roaming clients declared via reachable_via, so infra hosts can route to them via the gateway.
  def compute_allowed_ips(peer, data, is_roaming, use_gateway, primary_gateway_assigned)
    peer_is_gateway = data.key?('internet')
    ipv4 = data['wg0']['ip']
    ipv6 = data['wg0']['ipv6']

    if is_roaming && use_gateway
      return '0.0.0.0/0, ::/0', primary_gateway_assigned
    elsif is_roaming && !use_gateway
      return roaming_no_gateway_ips(peer_is_gateway, ipv4, ipv6, primary_gateway_assigned)
    end

    # Regular (non-roaming) host: route specific IPs only.
    # For gateway peers, also append IPs of roaming clients reachable via this gateway,
    # so infra hosts can reach them (e.g. earth via fishfinger) without a direct peer block.
    ips = ipv6 ? "#{ipv4}/32, #{ipv6}/128" : "#{ipv4}/32"
    if peer_is_gateway
      extra = extra_ips_via_gateway(peer)
      ips = ([ips] + extra).join(', ') unless extra.empty?
    end
    [ips, primary_gateway_assigned]
  end

  # Computes AllowedIPs for a roaming client that has gateway: false.
  # Primary internet gateway gets the full mesh subnet for routing all mesh traffic;
  # subsequent gateways and regular peers get only their specific IPs.
  def roaming_no_gateway_ips(peer_is_gateway, ipv4, ipv6, primary_gateway_assigned)
    if peer_is_gateway && !primary_gateway_assigned
      return '192.168.2.0/24, fd42:beef:cafe:2::/64', true
    end

    ips = ipv6 ? "#{ipv4}/32, #{ipv6}/128" : "#{ipv4}/32"
    [ips, primary_gateway_assigned]
  end
end

# InstallConfig is a utility class for managing the installation,
# configuration, and restarting of Wireguard on a remote host. It uses SSH and
# SCP for remote operations.
InstallConfig = Struct.new(:myself, :hosts) do
  def initialize(myself, hosts)
    @myself = myself

    data = hosts[myself]
    @os = data['os']
    domain = data.dig('lan', 'domain') || data.dig('internet', 'domain')
    @fqdn = "#{myself}.#{domain}"
    @ssh_user = data['ssh']['user']
    @ssh_port = data.dig('ssh', 'port') || 22
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
    owner_group = @os == 'Linux' ? 'root:root' : 'root:wheel'
    ssh <<~SH
      if [ ! -d #{@conf_dir} ]; then
        #{@sudo_cmd} mkdir -p #{@conf_dir}
      fi
      #{@sudo_cmd} chmod 700 #{@conf_dir}
      #{@sudo_cmd} mv -v wg0.conf #{@conf_dir}
      #{@sudo_cmd} chown #{owner_group} #{@conf_dir}/wg0.conf
      #{@sudo_cmd} chmod 600 #{@conf_dir}/wg0.conf
      if command -v restorecon >/dev/null 2>&1; then
        #{@sudo_cmd} restorecon -v #{@conf_dir}/wg0.conf || true
      fi
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
      Net::SCP.upload!(@fqdn, @ssh_user, src, dst, ssh: { port: @ssh_port })
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
    Net::SSH.start(@fqdn, @ssh_user, port: @ssh_port) do |ssh|
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
    # Generate Wireguard configuration for the host.
    WireguardConfig.new(host, conf['hosts']).generate! if options[:generate]
    # Install Wireguard configuration for the host (only for hosts with ssh section).
    if options[:install] && conf['hosts'][host].key?('ssh')
      InstallConfig.new(host, conf['hosts']).upload!.install!.reload!
    end
    # Clean Wireguard configuration for the host.
    WireguardConfig.new(host, conf['hosts']).clean! if options[:clean]
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 2
end
