#!/usr/bin/env ruby

require 'yaml'
require 'fileutils'

# Generates Wireguard keys and config files for each host
class KeyTool
  def initialize(myself)
    raise 'Wireguard tool not found' unless system('which wg > /dev/null 2>&1')

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
  def genpsk! = File.write(@preshared_path, `wg genpsk`)

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

PeerSnippet = Struct.new(:myself, :domain, :allowed_ips, :endpoint) do
  def to_s
    keys = KeyTool.new(myself)
    <<~PEER_CONFIG
      [Peer]
      # #{myself}.#{domain}
      PublicKey = #{keys.pub}
      PresharedKey = #{keys.preshared}
      Endpoint = #{endpoint}:56709
      AllowedIPs = #{allowed_ips}/32
    PEER_CONFIG
  end
end

WireguardConfig = Struct.new(:myself, :hosts) do
  def to_s
    peers = hosts.reject { _1 == myself }.map do |hostname, data|
      PeerSnippet.new(hostname, data['wg0']['domain'], data['wg0']['ip'], data['lan']['ip'])
    end

    keys = KeyTool.new(myself)
    <<~CONFIG
      [Interface]
      # #{myself}.#{hosts[myself]['wg0']['domain']}
      Address = #{hosts[myself]['wg0']['ip']}
      PrivateKey = #{keys.priv}
      PresharedKey = #{keys.preshared}
      ListenPort = 56709

      #{peers.map(&:to_s).join("\n")}
    CONFIG
  end

  def generate!
    dist_dir = "dist/#{myself}/etc/wireguard"
    FileUtils.mkdir_p(dist_dir) unless Dir.exist?(dist_dir)
    File.write("#{dist_dir}/wg0.conf", to_s)
  end
end

CONFIG = YAML.load_file('wireguardmeshgenerator.yaml').freeze
CONFIG['hosts'].each_key do |hostname|
  WireguardConfig.new(hostname, CONFIG['hosts']).generate!
end
