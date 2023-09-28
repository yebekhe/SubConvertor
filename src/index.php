<?php
include "functions.php";
include "ipAccessLimit.php";
error_reporting(0);
header("Content-type: application/json;");

/** Check if subscription is base64 encoded or not */
function is_base64_encoded($string)
{
    if (base64_encode(base64_decode($string, true)) === $string) {
        return true;
    } else {
        return false;
    }
}
function getCipher(array $decoded_config) {
    return isset($decoded_config["scy"])
        ? $decoded_config["scy"]
        : "auto";
}

function getUUID(array $decoded_config) {
    if (is_valid_uuid($decoded_config["id"]) === false){
        return null;
    }
    return str_replace(" ", "+", $decoded_config["id"]);
}

function getVMessTLS(array $decoded_config) {
    return $decoded_config["tls"] === "tls" ? true : false;
}

function processVmessClash($decoded_config, $outboundType, $countHelper)
{
    if ($decoded_config["ps"] === "") {
        return null;
    }
    if (is_null(getUUID($decoded_config))){
        return null;
    }
    
    if ($outboundType === "clash" || $outboundType === "meta") {
        $vmessTemplate = [
            "name" => $decoded_config["ps"]  . " | " . numberToEmoji($countHelper),
            "type" => "vmess",
            "server" => $decoded_config["add"],
            "port" => $decoded_config["port"],
            "cipher" => getCipher($decoded_config),
            "uuid" => getUUID($decoded_config),
            "alterId" => isset($decoded_config["aid"]) ? $decoded_config["aid"] : "0",
            "tls" => getVMessTLS($decoded_config),
            "skip-cert-verify" => true,
            "network" => isset($decoded_config["net"]) ? $decoded_config["net"] : "tcp"
        ];
    
        if ($vmessTemplate["network"] === "ws") {
            $path = htmlentities($decoded_config["path"], ENT_QUOTES);
            $vmessTemplate['ws-opts'] = [
                "path" => $path,
                "headers" => [
                    "host" => $decoded_config["host"]
                ]
            ];
        } elseif ($vmessTemplate["network"] === "grpc") {
            $servicename = htmlentities($decoded_config["path"], ENT_QUOTES);
            $vmessTemplate['grpc-opts'] = [
                "grpc-service-name" => $servicename,
                "grpc-mode" => $decoded_config["type"]
            ];
        }

        return "  - " . json_encode($vmessTemplate, JSON_UNESCAPED_UNICODE);
    } elseif ($outboundType === "surfboard") {
        $networkType = isset($decoded_config["net"]) ? $decoded_config["net"] : "tcp";
        $alterId = isset($decoded_config["aid"]) ? $decoded_config["aid"] : "0";
        $AEAD = ($alterId === "0") ? "true" : "false";
        if ($networkType === "ws") {
            $vmessTemplate = $decoded_config["ps"]  . " | " . numberToEmoji($countHelper) . " = vmess, " .
            $decoded_config["add"] . ", " .
            $decoded_config["port"] .
            ", username = " . getUUID($decoded_config) .
            ", ws = true, tls = " . getVMessTLS($decoded_config) .
            ", vmess-aead = " . $AEAD .
            ", ws-path = " . htmlentities($decoded_config["path"], ENT_QUOTES) .
            ', ws-headers = Host:"' . $decoded_config["host"] .
            '", skip-cert-verify = true, tfo = false';
        }
        return str_replace(",,", ",", $vmessTemplate);
    } else {
        return null;
    }
}

function processTrojanClash(array $decoded_config, $outboundType, $countHelper)
{
    if ($decoded_config["hash"] === "") {
        return null;
    }
    
    if ($outboundType === "clash" || $outboundType === "meta") {
        $trojanTemplate = [
            "name" => $decoded_config["hash"] . " | " . numberToEmoji($countHelper) ,
            "type" => "trojan",
            "server" => $decoded_config["hostname"],
            "port" => $decoded_config["port"],
            "udp" => false,
            "password" => $decoded_config["username"],
            "skip-cert-verify" => isset($decoded_config["params"]["allowInsecure"]) && $decoded_config["params"]["allowInsecure"] === "1" ? true : false,
            "network" => "tcp",
            "client-fingerprint" => "chrome"
        ];
        if (isset($decoded_config["params"]["sni"])) {
            $trojanTemplate["sni"] = $decoded_config["params"]["sni"];
        }
        return "  - " . json_encode($trojanTemplate, JSON_UNESCAPED_UNICODE);
    } elseif ($outboundType === "surfboard") {
        $skipCertVerify = isset($decoded_config["params"]["allowInsecure"]) && $decoded_config["params"]["allowInsecure"] === "1" ? "true" : "false";
        if (isset($decoded_config["params"]["sni"])) {
            $trojanSni = ", sni = " . $decoded_config["params"]["sni"];
        } else {
            $trojanSni = "";
        }
        $trojanTemplate = $decoded_config["hash"] . " | " . numberToEmoji($countHelper) . " = trojan, " .
        $decoded_config["hostname"] . ", " .
        $decoded_config["port"] .
        ", password = " . $decoded_config["username"] .
        ", udp-delay = true, skip-cert-verify = " . $skipCertVerify .
        $trojanSni .
        ", ws = false";

        return $trojanTemplate;
    }
}

function processShadowsocksClash(array $decoded_config, $outboundType, $countHelper)
{
    if ($decoded_config["name"] === "" || $decoded_config["name"] === null) {
        return null;
    }
    if (!is_string($decoded_config["password"])) {
        return null;
    }
    
    if ($outboundType === "clash" || $outboundType === "meta") {
        $shadowsocksTemplate = [
            "name" => $decoded_config["name"]  . " | " . numberToEmoji($countHelper),
            "type" => "ss",
            "server" => $decoded_config["server_address"],
            "port" => $decoded_config["server_port"],
            "password" => $decoded_config["password"],
            "cipher" => $decoded_config["encryption_method"]
        ];
        return "  - " . json_encode($shadowsocksTemplate, JSON_UNESCAPED_UNICODE);
    } elseif ($outboundType === "surfboard") {
        $shadowsocksTemplate = $decoded_config["name"]  . " | " . numberToEmoji($countHelper) . " = ss, " . 
        $decoded_config["server_address"] . ", " .
        $decoded_config["server_port"] .
        ", encrypt-method = " . $decoded_config["encryption_method"] .
        ", password = " . $decoded_config["password"];
        return $shadowsocksTemplate;
    }
}
function is_valid_uuid($uuid_string) {
    $pattern = '/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/i';
    return (bool) preg_match($pattern, $uuid_string);
  }

function getPort(array $decoded_config) {
    return isset($decoded_config["port"]) && $decoded_config["port"] !== "" ? $decoded_config["port"] : 443;
}

function getTls(array $decoded_config) {
    return isset($decoded_config["params"]["security"]) && $decoded_config["params"]["security"] === "tls" ? true : false;
}


function getNetwork(array $decoded_config) {
    return isset($decoded_config["params"]["type"]) ? $decoded_config["params"]["type"] : "tcp";
}

function getUsername(array $decoded_config){
    if (is_valid_uuid($decoded_config["username"]) === false){
        return null;
    }
    return $decoded_config["username"];
}

function processVlessClash(array $decoded_config, $outboundType, $countHelper) {
    if ($decoded_config["hash"] === "" || is_null($decoded_config["hash"])) {
        return null;
    }
    if (is_null(getUsername($decoded_config))){
        return null;
    }
    
    if ($outboundType === "meta") {
        $vlessTemplate = [
            "name" => $decoded_config["hash"] . " | " . numberToEmoji($countHelper),
            "type" => "vless",
            "server" => $decoded_config["hostname"],
            "port" => getPort($decoded_config),
            "udp" => false,
            "uuid" => getUsername($decoded_config),
            "tls" => getTls($decoded_config),
            "network" => getNetwork($decoded_config)
        ];
        if (isset($decoded_config["params"]["sni"])) {
            $vlessTemplate['servername'] = $decoded_config["params"]["sni"];
        }
        if (isset($decoded_config["params"]["flow"])) {
            $vlessTemplate["flow"] = "xtls-rprx-vision";
        }
        if ($vlessTemplate['network'] === "ws") {
            $path = isset($decoded_config["params"]["path"]) ? htmlentities($decoded_config["params"]["path"], ENT_QUOTES) : "/";
            $vlessTemplate['ws-opts'] = [
                "path" => $path
            ];
            if (isset($decoded_config["params"]["host"])) {
                $vlessTemplate['ws-opts']["headers"] = [
                    "host" => $decoded_config["params"]["host"]
                ];
            }
        } elseif ($vlessTemplate['network'] === "grpc" && isset($decoded_config["params"]["serviceName"])) {
            $vlessTemplate['grpc-opts'] =[
                "grpc-service-name" => $decoded_config["params"]["serviceName"]
            ];
        }
        if (!is_null($decoded_config["params"]["security"]) && $decoded_config["params"]["security"] === "reality") {
            $vlessTemplate['reality-opts'] = [
                "public-key" => $decoded_config["params"]["pbk"],
                "client-fingerprint" => "chrome"
            ];
            if (!is_null($decoded_config["params"]["sid"]) && $decoded_config["params"]["sid"] !== "") {
                $vlessTemplate['reality-opts']['short-id'] = $decoded_config["params"]["sid"];
            }
        }
        return "  - " . json_encode($vlessTemplate, JSON_UNESCAPED_UNICODE);
    } else {
        return null;
    }
}

function processConvert($config, $type, $outboundType, $countHelper)
{
    switch ($type) {
        case "vmess":
            return processVmessClash($config, $outboundType, $countHelper);
        case "vless":
            return processVlessClash($config, $outboundType, $countHelper);
        case "trojan":
            return processTrojanClash($config, $outboundType, $countHelper);
        case "ss":
            return processShadowsocksClash($config, $outboundType, $countHelper);
    }
}

function generate_proxies($input, $outboundType, $urlOrConfig)
{
    $proxies = "";
    
    if ($urlOrConfig === "sub") {
        if (is_base64_encoded(file_get_contents($input))) {
            $v2ray_subscription = base64_decode(
                file_get_contents($input),
                true
            );
        } else {
            $v2ray_subscription = file_get_contents($input);
        }
    } elseif ($urlOrConfig === "config") {
        $v2ray_subscription = base64_decode($input, true);
    }
    $v2ray_subscription = str_replace(" ", "%20", $v2ray_subscription);
    $pattern = '/(\w+:\/\/[^\s]+)/'; // Regular expression pattern

    preg_match_all($pattern, $v2ray_subscription, $matches);

    $configs_array = $matches[0];

    //$configs_array = explode("\n", $v2ray_subscription);
    $suitable_config = suitable_output($configs_array, $outboundType);
    $countHelper = 1;
    foreach ($suitable_config as $config) {
        $type = detect_type($config);
        $config = str_replace("%20", " ", $config);
        $typeArray = array("vmess", "vless", "trojan", "ss");
        if (in_array($type, $typeArray)){
            $decoded_config = parse_config($config, $type);
            $proxies .= !is_null(
                processConvert($decoded_config, $type, $outboundType, $countHelper)
            )
                ? processConvert($decoded_config, $type, $outboundType, $countHelper) . "\n"
                : null;

            $countHelper ++;
        }
    }

    return $proxies;
}

function suitable_output($input, $output_type)
{
    switch ($output_type) {
        case "clash":
        case "surfboard":
            foreach ($input as $key => $config) {
                if (detect_type($config) === "vless") {
                    unset($input[$key]);
                }
                if ($config === "trojan://" || $config === "ss://Og==@:") {
                    unset($input[$key]);
                }
            }
            break;
        case "meta":
            foreach ($input as $key => $config) {
                if ($config === "trojan://" || $config === "ss://Og==@:") {
                    unset($input[$key]);
                }
            }
            break;
    }
    return $input;
}

function extract_names($configs, $type)
{
    $configs_name = "";
    $configs_array = explode("\n", $configs);
    switch ($type) {
        case "meta":
        case "clash":
            //unset($configs_array[0]);
            $pattern = '/"name":"(.*?)"/';
            foreach ($configs_array as $config_data) {
                if (preg_match($pattern, $config_data, $matches)) {
                    $configs_name .= "      - '" . $matches[1] . "'\n";
                }
            }
            break;
        case "surfboard":
            foreach ($configs_array as $config_data) {
                $config_array = explode(" = ", $config_data);
                $configs_name .= $config_array[0] . ",";
            }
            break;
    }
    return str_replace(",,", ",", $configs_name);
}

function full_config($input, $type, $url, $urlOrConfig)
{   if ($urlOrConfig === "sub") {
        $surf_url = "https://yebekhe.link/api/toClash?url=" . urlencode($url) . "&type=sufrboard&process=full";
    } else {
        $surf_url = "https://yebekhe.link/api/toClash?config=" . urlencode($input) . "&type=sufrboard&process=full";
    }
    

    $config_start = get_config_start($type, $surf_url);
    $config_proxy_group = get_config_proxy_group($type);
    $config_proxy_rules = get_config_proxy_rules($type);

    $proxies = generate_proxies($input, $type, $urlOrConfig);
    $configs_name = extract_names($proxies, $type);
    $full_configs = generate_full_config(
        $config_start,
        $proxies,
        $config_proxy_group,
        $config_proxy_rules,
        $configs_name,
        $type
    );
    return $full_configs;
}

function get_config_start($type, $surf_url)
{
    return [
        "clash" => [
            "mixed-port: 7890",
            "allow-lan: true",
            "tcp-concurrent: true",
            "enable-process: true",
            "find-process-mode: always",
            "mode: rule",
            "log-level: error",
            "ipv6: true",
            "external-controller: 127.0.0.1:9090",
            "experimental:",
            "  ignore-resolve-fail: true",
            "  sniff-tls-sni: true",
            "  tracing: true",
            "hosts:",
            '  "localhost": 127.0.0.1',
            "profile:",
            "  store-selected: true",
            "  store-fake-ip: true",
            "",
            "sniffer:",
            "  enable: true",
            "  sniff:",
            "    http: { ports: [1-442, 444-8442, 8444-65535], override-destination: true }",
            "    tls: { ports: [1-79, 81-8079, 8081-65535], override-destination: true }",
            "  force-domain:",
            '      - "+.v2ex.com"',
            "      - www.google.com",
            "      - google.com",
            "  skip-domain:",
            "      - Mijia Cloud",
            "      - dlg.io.mi.com",
            "  sniffing:",
            "    - tls",
            "    - http",
            "  port-whitelist:",
            '    - "80"',
            '    - "443"',
            "",
            "tun:",
            "  enable: true",
            "  prefer-h3: true",
            "  listen: 0.0.0.0:53",
            "  stack: gvisor",
            "  dns-hijack:",
            '     - "any:53"',
            '     - "tcp://any:53"',
            "  auto-redir: true",
            "  auto-route: true",
            "  auto-detect-interface: true",
            "",
            "dns:",
            "  enable: true",
            "  ipv6: true",
            "  default-nameserver:",
            "    - 1.1.1.1", 
            "    - 8.8.8.8",
            "  enhanced-mode: fake-ip",
            "  fake-ip-range: 198.18.0.1/16",
            "  fake-ip-filter:",
            "    - 'stun.*.*'", 
            "    - 'stun.*.*.*'", 
            "    - '+.stun.*.*'", 
            "    - '+.stun.*.*.*'", 
            "    - '+.stun.*.*.*.*'", 
            "    - '+.stun.*.*.*.*.*'", 
            "    - '*.lan'", 
            "    - '+.msftncsi.com'", 
            "    - msftconnecttest.com", 
            "    - 'time?.*.com'", 
            "    - 'time.*.com'", 
            "    - 'time.*.gov'", 
            "    - 'time.*.apple.com'", 
            "    - time-ios.apple.com", 
            "    - 'time1.*.com'", 
            "    - 'time2.*.com'", 
            "    - 'time3.*.com'", 
            "    - 'time4.*.com'", 
            "    - 'time5.*.com'", 
            "    - 'time6.*.com'", 
            "    - 'time7.*.com'", 
            "    - 'ntp?.*.com'", 
            "    - 'ntp.*.com'", 
            "    - 'ntp1.*.com'", 
            "    - 'ntp2.*.com'", 
            "    - 'ntp3.*.com'", 
            "    - 'ntp4.*.com'", 
            "    - 'ntp5.*.com'", 
            "    - 'ntp6.*.com'", 
            "    - 'ntp7.*.com'", 
            "    - '+.pool.ntp.org'", 
            "    - '+.ipv6.microsoft.com'", 
            "    - speedtest.cros.wr.pvp.net", 
            "    - network-test.debian.org", 
            "    - detectportal.firefox.com", 
            "    - cable.auth.com", 
            "    - miwifi.com", 
            "    - routerlogin.com", 
            "    - routerlogin.net", 
            "    - tendawifi.com", 
            "    - tendawifi.net", 
            "    - tplinklogin.net", 
            "    - tplinkwifi.net", 
            "    - '*.xiami.com'", 
            "    - tplinkrepeater.net", 
            "    - router.asus.com", 
            "    - '*.*.*.srv.nintendo.net'", 
            "    - '*.*.stun.playstation.net'", 
            "    - '*.openwrt.pool.ntp.org'", 
            "    - resolver1.opendns.com", 
            "    - 'GC._msDCS.*.*'", 
            "    - 'DC._msDCS.*.*'", 
            "    - 'PDC._msDCS.*.*'",
            "  use-hosts: true",
            "  nameserver:",
            "    - 8.8.4.4", 
            "    - 1.0.0.1", 
            "    - https://1.0.0.1/dns-query", 
            "    - https://8.8.4.4/dns-query",
            "  nameserver-policy:",
            "    'RULE-SET:ir,ircidr,geoip:ir,+.ir,+.bonyan.co': [\"217.218.155.155\", \"217.218.127.127\", \"https://dns.403.online/dns-query\", \"https://dns.shecan.ir/dns-query\"]",
            ""
        ],
        "meta" => [
            "mixed-port: 7890",
            "allow-lan: true",
            "tcp-concurrent: true",
            "enable-process: true",
            "find-process-mode: always",
            "mode: rule",
            "log-level: error",
            "ipv6: true",
            "external-controller: 127.0.0.1:9090",
            "experimental:",
            "  ignore-resolve-fail: true",
            "  sniff-tls-sni: true",
            "  tracing: true",
            "hosts:",
            '  "localhost": 127.0.0.1',
            "profile:",
            "  store-selected: true",
            "  store-fake-ip: true",
            "",
            "sniffer:",
            "  enable: true",
            "  sniff:",
            "    http: { ports: [1-442, 444-8442, 8444-65535], override-destination: true }",
            "    tls: { ports: [1-79, 81-8079, 8081-65535], override-destination: true }",
            "  force-domain:",
            '      - "+.v2ex.com"',
            "      - www.google.com",
            "      - google.com",
            "  skip-domain:",
            "      - Mijia Cloud",
            "      - dlg.io.mi.com",
            "  sniffing:",
            "    - tls",
            "    - http",
            "  port-whitelist:",
            '    - "80"',
            '    - "443"',
            "",
            "tun:",
            "  enable: true",
            "  prefer-h3: true",
            "  listen: 0.0.0.0:53",
            "  stack: gvisor",
            "  dns-hijack:",
            '     - "any:53"',
            '     - "tcp://any:53"',
            "  auto-redir: true",
            "  auto-route: true",
            "  auto-detect-interface: true",
            "",
            "dns:",
            "  enable: true",
            "  ipv6: true",
            "  default-nameserver:",
            "    - 1.1.1.1", 
            "    - 8.8.8.8",
            "  enhanced-mode: fake-ip",
            "  fake-ip-range: 198.18.0.1/16",
            "  fake-ip-filter:",
            "    - 'stun.*.*'", 
            "    - 'stun.*.*.*'", 
            "    - '+.stun.*.*'", 
            "    - '+.stun.*.*.*'", 
            "    - '+.stun.*.*.*.*'", 
            "    - '+.stun.*.*.*.*.*'", 
            "    - '*.lan'", 
            "    - '+.msftncsi.com'", 
            "    - msftconnecttest.com", 
            "    - 'time?.*.com'", 
            "    - 'time.*.com'", 
            "    - 'time.*.gov'", 
            "    - 'time.*.apple.com'", 
            "    - time-ios.apple.com", 
            "    - 'time1.*.com'", 
            "    - 'time2.*.com'", 
            "    - 'time3.*.com'", 
            "    - 'time4.*.com'", 
            "    - 'time5.*.com'", 
            "    - 'time6.*.com'", 
            "    - 'time7.*.com'", 
            "    - 'ntp?.*.com'", 
            "    - 'ntp.*.com'", 
            "    - 'ntp1.*.com'", 
            "    - 'ntp2.*.com'", 
            "    - 'ntp3.*.com'", 
            "    - 'ntp4.*.com'", 
            "    - 'ntp5.*.com'", 
            "    - 'ntp6.*.com'", 
            "    - 'ntp7.*.com'", 
            "    - '+.pool.ntp.org'", 
            "    - '+.ipv6.microsoft.com'", 
            "    - speedtest.cros.wr.pvp.net", 
            "    - network-test.debian.org", 
            "    - detectportal.firefox.com", 
            "    - cable.auth.com", 
            "    - miwifi.com", 
            "    - routerlogin.com", 
            "    - routerlogin.net", 
            "    - tendawifi.com", 
            "    - tendawifi.net", 
            "    - tplinklogin.net", 
            "    - tplinkwifi.net", 
            "    - '*.xiami.com'", 
            "    - tplinkrepeater.net", 
            "    - router.asus.com", 
            "    - '*.*.*.srv.nintendo.net'", 
            "    - '*.*.stun.playstation.net'", 
            "    - '*.openwrt.pool.ntp.org'", 
            "    - resolver1.opendns.com", 
            "    - 'GC._msDCS.*.*'", 
            "    - 'DC._msDCS.*.*'", 
            "    - 'PDC._msDCS.*.*'",
            "  use-hosts: true",
            "  nameserver:",
            "    - 8.8.4.4", 
            "    - 1.0.0.1", 
            "    - https://1.0.0.1/dns-query", 
            "    - https://8.8.4.4/dns-query",
            "  nameserver-policy:",
            "    'RULE-SET:ir,ircidr,geoip:ir,+.ir,+.bonyan.co': [\"217.218.155.155\", \"217.218.127.127\", \"https://dns.403.online/dns-query\", \"https://dns.shecan.ir/dns-query\"]",
            ""
        ],
        "surfboard" => [
            "#!MANAGED-CONFIG " . $surf_url . " interval=60 strict=false",
            "",
            "[General]",
            "loglevel = notify",
            "interface = 127.0.0.1",
            "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local",
            "ipv6 = true",
            "dns-server = system, 223.5.5.5",
            "exclude-simple-hostnames = true",
            "enhanced-mode-by-rule = true",
        ],
    ][$type];
}

function get_config_proxy_group($type)
{
    return [
        "clash" => [
            "proxy-groups:" => [
                "MANUAL" => [
                    "  - name: MANUAL",
                    "    type: select",
                    "    proxies:",
                    "      - URL-TEST",
                    "      - FALLBACK",
                ],
                "URL-TEST" => [
                    "  - name: URL-TEST",
                    "    type: url-test",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    tolerance: 50",
                    "    proxies:",
                ],
                "FALLBACK" => [
                    "  - name: FALLBACK",
                    "    type: fallback",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    proxies:",
                ],
            ],
        ],
        "meta" => [
            "proxy-groups:" => [
                "MANUAL" => [
                    "  - name: MANUAL",
                    "    type: select",
                    "    proxies:",
                    "      - URL-TEST",
                    "      - FALLBACK",
                ],
                "URL-TEST" => [
                    "  - name: URL-TEST",
                    "    type: url-test",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    tolerance: 50",
                    "    proxies:",
                ],
                "FALLBACK" => [
                    "  - name: FALLBACK",
                    "    type: fallback",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    proxies:",
                ],
            ],
        ],
        "surfboard" => [
            "[Proxy Group]" => [
                "MANUAL = select,URL-TEST,FALLBACK,",
                "URL-TEST = url-test,",
                "FALLBACK = fallback,",
            ],
        ],
    ][$type];
}

function get_config_proxy_rules($type)
{
    return [
        "clash" => [
            "rule-providers:",
            "  ir: {type: http, format: text, behavior: domain, path: ./ruleset/ir.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ir.txt, interval: 86400}",
            "  ads: {type: http, format: text, behavior: domain, path: ./ruleset/ads.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ads.txt, interval: 86400}",
            "  ircidr: {type: http, format: text, behavior: ipcidr, path: ./ruleset/ircidr.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ircidr.txt, interval: 86400}",
            "  private: {type: http, format: text, behavior: ipcidr, path: ./ruleset/private.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/private.txt, interval: 86400}",
            "  apps: {type: http, format: text, behavior: domain, path: ./ruleset/apps.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/apps.txt, interval: 86400}",
            "  malware: {type: http, format: text, behavior: domain, path: ./ruleset/malware.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/malware.txt, interval: 86400}",
            "  phishing: {type: http, format: text, behavior: domain, path: ./ruleset/phishing.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/phishing.txt, interval: 86400}",
            "  cryptominers: {type: http, format: text, behavior: domain, path: ./ruleset/cryptominers.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/cryptominers.txt, interval: 86400}",
            "rules:", 
            "  - IP-CIDR,127.0.0.1/32,DIRECT,no-resolve",
            "  - IP-CIDR,198.18.0.1/16,DIRECT,no-resolve",
            "  - IP-CIDR,28.0.0.1/8,DIRECT,no-resolve",
            "  - IP-CIDR6,::1/128,DIRECT,no-resolve",
            "  - DOMAIN-SUFFIX,local,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-loopback,DIRECT",
            "  - DOMAIN-SUFFIX,lan,DIRECT",
            "  - DOMAIN-SUFFIX,localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ir,DIRECT",
            "  - DOMAIN,clash.razord.top,DIRECT",
            "  - DOMAIN,yacd.haishan.me,DIRECT",
            "  - DOMAIN,yacd.metacubex.one,DIRECT",
            "  - DOMAIN,clash.metacubex.one,DIRECT",
            "  - RULE-SET,ads,REJECT",
            "  - RULE-SET,malware,REJECT",
            "  - RULE-SET,phishing,REJECT",
            "  - RULE-SET,cryptominers,REJECT",
            "  - RULE-SET,private,DIRECT",
            "  - RULE-SET,apps,DIRECT",
            "  - RULE-SET,ir,DIRECT",
            "  - RULE-SET,ircidr,DIRECT",
            "  - MATCH,MANUAL"
        ],
        "meta" => [
            "rule-providers:",
            "  ir: {type: http, format: text, behavior: domain, path: ./ruleset/ir.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ir.txt, interval: 86400}",
            "  ads: {type: http, format: text, behavior: domain, path: ./ruleset/ads.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ads.txt, interval: 86400}",
            "  ircidr: {type: http, format: text, behavior: ipcidr, path: ./ruleset/ircidr.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ircidr.txt, interval: 86400}",
            "  private: {type: http, format: text, behavior: ipcidr, path: ./ruleset/private.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/private.txt, interval: 86400}",
            "  apps: {type: http, format: text, behavior: domain, path: ./ruleset/apps.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/apps.txt, interval: 86400}",
            "  malware: {type: http, format: text, behavior: domain, path: ./ruleset/malware.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/malware.txt, interval: 86400}",
            "  phishing: {type: http, format: text, behavior: domain, path: ./ruleset/phishing.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/phishing.txt, interval: 86400}",
            "  cryptominers: {type: http, format: text, behavior: domain, path: ./ruleset/cryptominers.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/cryptominers.txt, interval: 86400}",
            "rules:", 
            "  - IP-CIDR,127.0.0.1/32,DIRECT,no-resolve",
            "  - IP-CIDR,198.18.0.1/16,DIRECT,no-resolve",
            "  - IP-CIDR,28.0.0.1/8,DIRECT,no-resolve",
            "  - IP-CIDR6,::1/128,DIRECT,no-resolve",
            "  - DOMAIN-SUFFIX,local,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-loopback,DIRECT",
            "  - DOMAIN-SUFFIX,lan,DIRECT",
            "  - DOMAIN-SUFFIX,localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ir,DIRECT",
            "  - DOMAIN,clash.razord.top,DIRECT",
            "  - DOMAIN,yacd.haishan.me,DIRECT",
            "  - DOMAIN,yacd.metacubex.one,DIRECT",
            "  - DOMAIN,clash.metacubex.one,DIRECT",
            "  - RULE-SET,ads,REJECT",
            "  - RULE-SET,malware,REJECT",
            "  - RULE-SET,phishing,REJECT",
            "  - RULE-SET,cryptominers,REJECT",
            "  - RULE-SET,private,DIRECT",
            "  - RULE-SET,apps,DIRECT",
            "  - RULE-SET,ir,DIRECT",
            "  - RULE-SET,ircidr,DIRECT",
            "  - MATCH,MANUAL"
        ],
        "surfboard" => [
            "[Rule]", 
            "GEOIP,IR,DIRECT", 
            "FINAL,MANUAL"
        ],
    ][$type];
}

function array_to_string($input)
{
    return implode("\n", $input);
}

function reprocess($input){
    $input = str_replace("  - ", "", $input);
    $proxies_array = explode("\n", $input);
    foreach ($proxies_array as $proxy_json){
        $proxy_array = json_decode($proxy_json, true);
        
        $output[] = "  - " . json_encode($proxy_array, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
    return str_replace("  - null", "", implode("\n", $output));
}

function generate_full_config(
    $config_start,
    $proxies,
    $config_proxy_group,
    $config_proxy_rules,
    $configs_name,
    $type
) {
    $config_start_string = array_to_string($config_start);
    switch ($type) {
        case "clash":
        case "meta":
            $proxies = "proxies:\n" . $proxies;
            $proxy_group_string = "proxy-groups:";
            $proxy_group_manual =
                array_to_string(
                    $config_proxy_group["proxy-groups:"]["MANUAL"]
                ) .
                "\n" .
                $configs_name;
            $proxy_group_urltest =
                array_to_string(
                    $config_proxy_group["proxy-groups:"]["URL-TEST"]
                ) .
                "\n" .
                $configs_name;
            $proxy_group_fallback =
                array_to_string(
                    $config_proxy_group["proxy-groups:"]["FALLBACK"]
                ) .
                "\n" .
                $configs_name;
            break;
        case "surfboard":
            $proxies = "\n[Proxy]\nDIRECT = direct\n" . $proxies;
            $proxy_group_string = "[Proxy Group]";
            $proxy_group_manual =
                $config_proxy_group["[Proxy Group]"][0] . $configs_name . "\n";
            $proxy_group_manual = str_replace(",,", "", $proxy_group_manual);
            $proxy_group_urltest =
                $config_proxy_group["[Proxy Group]"][1] . $configs_name . "\n";
            $proxy_group_urltest = str_replace(",,", "", $proxy_group_urltest);
            $proxy_group_fallback =
                $config_proxy_group["[Proxy Group]"][2] . $configs_name . "\n";
            $proxy_group_fallback = str_replace(
                ",,",
                "",
                $proxy_group_fallback
            );
            break;
    }
    $proxy_group_string .=
        "\n" .
        $proxy_group_manual .
        $proxy_group_urltest .
        $proxy_group_fallback;
    $proxy_rules = array_to_string($config_proxy_rules);
    $output =
        $config_start_string .
        "\n" .
        $proxies .
        $proxy_group_string .
        $proxy_rules;
    return $output;
}

$url = filter_input(INPUT_GET, "url", FILTER_VALIDATE_URL);
$config= filter_input(INPUT_GET, "config", FILTER_SANITIZE_STRING);
$type = filter_input(INPUT_GET, "type", FILTER_SANITIZE_STRING);
$process = filter_input(INPUT_GET, "process", FILTER_SANITIZE_STRING);
$protocol = filter_input(INPUT_GET, "protocol", FILTER_SANITIZE_STRING);
$type_array = ["clash", "meta", "surfboard"];

//checkIPAccessLimit("45.95.147.155", 600);
  
try {
    if (!$url && !$config) {
        throw new Exception("url or config parameter is missing or invalid");
    }

    if (!$type or !in_array($type, $type_array)) {
        $type = "surfboard";
    }
          
    if (!$process) {
        $process = "full";
    }

    if ($process === "name") {
      if ($url) {
          echo extract_names(generate_proxies($url, $type, "sub"), $type);
      } elseif ($config) {
          echo extract_names(generate_proxies(urldecode($config), $type, "config"), $type);
      }
    } elseif ($process === "proxies") {
        if ($url) {
            echo generate_proxies($url, $type, "sub");
        } else {
            echo generate_proxies(urldecode($config), $type, "config");
        }
    } elseif ($process === "full") {
        
        if ($url) {
            echo str_replace("\\", "", full_config($url, $type, $url, "sub"));
        } else {
            echo str_replace("\\", "", full_config(urldecode($config), $type, "" , "config"));
        }
        
    }
} catch (Exception $e) {
    $output = [
        "ok" => false,
        "result" => $e->getMessage(),
    ];
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}
