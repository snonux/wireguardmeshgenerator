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
    <<~PEER_CONF
      [Peer]
      # #{myself}.#{domain} as #{myself}.#{wgdomain}
      PublicKey = #{keytool.pub}
      PresharedKey = #{keytool.psk(peer)}
      AllowedIPs = #{allowed_ips}/32
      #{endpoint_str}
    PEER_CONF
  end

  def endpoint_str
    return '# Due to NAT no Endpoint configured' if endpoint == :behind_nat

    "Endpoint = #{endpoint}:56709"
  end
end

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

  def clean!
    %w[dist keys].select { |dir| Dir.exist?(dir) }.each do |dir|
      FileUtils.rm_r(dir)
    end
  end

  def generate!
    dist_dir = "dist/#{myself}/etc/wireguard"
    puts "Generating #{dist_dir}/wg0.conf"
    FileUtils.mkdir_p(dist_dir) unless Dir.exist?(dist_dir)
    File.write("#{dist_dir}/wg0.conf", to_s)
  end

  private

  def address
    return '# No Address = ... for OpenBSD here' if hosts[myself]['os'] == 'OpenBSD'

    "Address = #{hosts[myself]['wg0']['ip']}"
  end

  def peers
    excluded = hosts[myself].fetch('exclude_peers', []) << myself
    i_am_in_lan = hosts[myself].key?('lan')

    hosts.reject { excluded.include?(_1) }.map do |peer, data|
      peer_is_in_lan = data.key?('lan')
      reach = data[peer_is_in_lan ? 'lan' : 'internet']
      endpoint = if peer_is_in_lan == i_am_in_lan ||
                    !peer_is_in_lan
                   reach['ip']
                 else
                   :behind_nat
                 end
      PeerSnippet.new(peer, myself, reach['domain'], data['wg0']['domain'],
                      data['wg0']['ip'], endpoint)
    end
  end
end

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

  def upload!
    wg0_conf = "dist/#{@myself}/etc/wireguard/wg0.conf"
    scp(wg0_conf)
    self
  end

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

  def restart!
    puts "Reloading Wireguard on #{@myself}"
    ssh <<~SH
      #{@sudo_cmd} #{@reload_cmd}
      #{@sudo_cmd} wg show
    SH
  end

  private

  def scp(src, dst = '.')
    puts "Uploading #{src} to #{@fqdn}:#{dst}"
    raise "Upload #{srd} to #{@fqdn}:#{dst} failed" unless
      Net::SCP.upload!(@fqdn, @ssh_user, src, dst)
  end

  def ssh(cmd)
    File.write('cmd.sh', <<~SH) and scp('cmd.sh')
      #!/bin/sh
      set -x
      #{cmd}
      rm $0
    SH
    File.delete('cmd.sh') if File.exist?('cmd.sh')
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
    WireguardConfig.new(host, conf['hosts']).generate! if options[:generate]
    InstallConfig.new(host, conf['hosts']).upload!.install!.restart! if options[:install]
    WireguardConfig.new(host, conf['hosts']).clean! if options[:clean]
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 2
end
