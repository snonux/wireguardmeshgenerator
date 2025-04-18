#!/usr/bin/ruby

require 'fileutils'

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

PeerSnippet = Struct.new(:description, :public_key, :preshared_key, :allowed_ips) do
  def to_s
    <<~PEER_CONFIG
      [Peer]
      # #{description}
      PublicKey = #{public_key}
      PresharedKey = #{preshared_key}
      AllowedIPs = #{allowed_ips}
    PEER_CONFIG
  end
end

WireguardConfig = Struct.new(:myself, :hosts) do
  @peers = hosts.map do |name, data|
    PeerSnippet.new("#{name}.#{data[:wg0][:domain]}",
                    :PUB_KEY, :PRESHARED_KEY, "#{data[:wg0][:ip]}/32")
  end

  def to_s
    <<~CONFIG
      [Interface]
      Address = #{hosts[myself][:wg0][:ip]}
      PrivateKey = #{private_key}

      #{@peers.map(&:to_s).join("\n")}
    CONFIG
  end

  private

  def private_key = 'PRIVATE_KEY'
end

HOSTS.each_key do |name|
  config_dir = "dist/#{name}/etc/wireguard"
  config_path = "#{config_dir}/wg0.conf"
  FileUtils.mkdir_p(config_dir) unless Dir.exist?(config_dir)

  wg0 = WireguardConfig.new(name, HOSTS)
  puts "Generating config for #{name} at #{config_path}"
  File.write(config_path, wg0.to_s)
end
