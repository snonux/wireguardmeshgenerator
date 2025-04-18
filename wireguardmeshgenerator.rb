#!/usr/bin/env ruby

require 'fileutils'

WIREGUARD_TOOL = '/usr/bin/wg'.freeze
HOSTS = {
  f0: { lan: { domain: 'lan.buetow.org', ip: '192.168.1.130' },
        wg0: { domain: 'wg0.buetow.org', ip: '192.168.2.130' } },
  f1: { lan: { domain: 'lan.buetow.org', ip: '192.168.1.131' },
        wg0: { domain: 'wg0.buetow.org', ip: '192.168.2.131' } },
  f2: { lan: { domain: 'lan.buetow.org', ip: '192.168.1.132' },
        wg0: { domain: 'wg0.buetow.org', ip: '192.168.2.132' } },
  r0: { lan: { domain: 'lan.buetow.org', ip: '192.168.1.120' },
        wg0: { domain: 'wg0.buetow.org', ip: '192.168.2.120' } },
  r1: { lan: { domain: 'lan.buetow.org', ip: '192.168.1.121' },
        wg0: { domain: 'wg0.buetow.org', ip: '192.168.2.121' } },
  r2: { lan: { domain: 'lan.buetow.org', ip: '192.168.1.122' },
        wg0: { domain: 'wg0.buetow.org', ip: '192.168.2.122' } }
}.freeze

# Generates Wireguard keys and config files for each host
class KeyTool
  def initialize(myself)
    keys_dir = "keys/#{myself}/"
    FileUtils.mkdir_p(keys_dir) unless Dir.exist?(keys_dir)

    @pubkey_path = "#{keys_dir}/pubkey"
    @privkey_path = "#{keys_dir}/privkey"
    @preshared_path = "#{keys_dir}/preshared"

    generate! if !File.exist?(@pubkey_path) ||
                 !File.exist?(@privkey_path) ||
                 !File.exist?(@preshared_path)
  end

  def pub = File.read(@pubkey_path).strip
  def priv = File.read(@privkey_path).strip
  def preshared = File.read(@preshared_path).strip

  private

  def generate! = gen_privpub! && genpsk!
  def genpsk! = File.write(@preshared_path, `#{WIREGUARD_TOOL} genpsk`)

  def gen_privpub!
    privkey = IO.popen("#{WIREGUARD_TOOL} genkey", 'r+', &:read)
    IO.popen("#{WIREGUARD_TOOL} pubkey", 'r+') do |io|
      io.puts(privkey)
      io.close_write
      File.write(@privkey_path, privkey)
      File.write(@pubkey_path, io.read)
    end
  end
end

PeerSnippet = Struct.new(:myself, :domain, :allowed_ips) do
  def to_s
    keys = KeyTool.new(myself)
    <<~PEER_CONFIG
      [Peer]
      # #{myself}.#{domain}
      PublicKey = #{keys.pub}
      PresharedKey = #{keys.preshared}
      AllowedIPs = #{allowed_ips}/32
    PEER_CONFIG
  end
end

WireguardConfig = Struct.new(:myself, :hosts) do
  def to_s
    peers = hosts.reject { _1 == myself }.map do |hostname, data|
      PeerSnippet.new(hostname, data[:wg0][:domain], data[:wg0][:ip])
    end

    keys = KeyTool.new(myself)
    <<~CONFIG
      [Interface]
      # #{myself}.#{hosts[myself][:wg0][:domain]}
      Address = #{hosts[myself][:wg0][:ip]}
      PrivateKey = #{keys.priv}
      PresharedKey = #{keys.preshared}

      #{peers.map(&:to_s).join("\n")}
    CONFIG
  end
end

HOSTS.each_key do |hostname|
  raise 'Wireguard tool not found' unless File.exist?(WIREGUARD_TOOL)

  config_dir = "dist/#{hostname}/etc/wireguard"
  key_dir = "keys/#{hostname}/"
  config_path = "#{config_dir}/wg0.conf"
  [config_dir, key_dir].each { FileUtils.mkdir_p(_1) unless Dir.exist?(_1) }

  wg0 = WireguardConfig.new(hostname, HOSTS)
  puts "Generating config for #{hostname} at #{config_path}"
  File.write(config_path, wg0.to_s)
end
