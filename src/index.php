<?php
include "functions.php";
error_reporting(0);
header("Content-type: application/json;");

/** Check if subscription is base64 encoded or not */
function is_base64_encoded($string)
{
    if (base64_encode(base64_decode($string, true)) === $string) {
        return "true";
    } else {
        return "false";
    }
}
function getCipher(array $decoded_config) {
    return isset($decoded_config["scy"])
        ? ',"cipher":"' . $decoded_config["scy"] . '"'
        : ',"cipher":"auto"';
}

function getUUID(array $decoded_config) {
    return str_replace(" ", "+", $decoded_config["id"]);
}

function getVMessTLS(array $decoded_config) {
    return $decoded_config["tls"] === "tls" ? "true" : "false";
}

function getOpts(array $decoded_config) {
    $network = isset($decoded_config["net"]) ? $decoded_config["net"] : "tcp";
    switch ($network) {
        case "ws":
            $path = htmlentities($decoded_config["path"], ENT_QUOTES);
            $host = $decoded_config["host"];
            return ',"ws-opts":{"path":"' .
                $path .
                '","headers":{"host":"' .
                $host .
                '"}}';
        case "grpc":
            $servicename = htmlentities($decoded_config["path"], ENT_QUOTES);
            $mode = $decoded_config["type"];
            return ',"grpc-opts":{"grpc-service-name":"' .
                $servicename .
                '","grpc-mode":"' .
                $mode .
                '"}';
        case "tcp":
            return "";
    }
}

function getVMessAEAD(array $decoded_config) {
    $alterId = $decoded_config["aid"];
    return $alterId === "0" ? "true" : "false";
}

function process_vmess_clash(array $decoded_config, $output_type)
{
    $name = $decoded_config["ps"];
    if ($name === "") {
        return null;
    }
    $server = $decoded_config["add"];
    $port = $decoded_config["port"];
    $cipher = getCipher($decoded_config);
    $uuid = getUUID($decoded_config);
    $alterId = $decoded_config["aid"];
    $tls = getVMessTLS($decoded_config);
    $network = isset($decoded_config["net"]) ? $decoded_config["net"] : "tcp";
    $opts = getOpts($decoded_config);
    $vmess_aead = getVMessAEAD($decoded_config);
    
    switch ($output_type) {
        case "clash":
        case "meta":
            $vm_template =
                '  - {"name":"' .
                $name .
                '","type":"vmess","server":"' .
                $server .
                '","port":' .
                $port .
                $cipher .
                ',"uuid":"' .
                $uuid .
                '","alterId":' .
                $alterId .
                ',"tls":' .
                $tls .
                ',"skip-cert-verify":true,"network":"' .
                $network .
                '"' .
                $opts .
                ',"client-fingerprint":"chrome"}';
            break;
        case "surfboard":
            if ($network === "ws") {
                $vm_template =
                    $name .
                    " = vmess, " .
                    $server .
                    ", " .
                    $port .
                    ", username = " .
                    $uuid .
                    ", ws = true, tls = " .
                    $tls .
                    ", vmess-aead = " .
                    $vmess_aead .
                    ", ws-path = " .
                    htmlentities($decoded_config["path"], ENT_QUOTES) .
                    ', ws-headers = Host:"' .
                    $decoded_config["host"] .
                    '", skip-cert-verify = true, tfo = false';
            } else {
                return null;
            }
            break;
    }

    return str_replace(",,", ",", $vm_template);
}

function process_trojan_clash(array $decoded_config, $output_type)
{
    $name = $decoded_config["hash"];
    if ($name === "") {
        return null;
    }
    $server = $decoded_config["hostname"];
    $port = $decoded_config["port"];
    $username = $decoded_config["username"];
    $sni = isset($decoded_config["params"]["sni"])
        ? ',"sni":"' . $decoded_config["params"]["sni"] . '"'
        : "";
    $skip_cert =
        isset($decoded_config["params"]["allowInsecure"]) &&
        $decoded_config["params"]["allowInsecure"] === "1"
            ? "true"
            : "false";
    switch ($output_type) {
        case "clash":
        case "meta":
            $tr_template =
                '  - {"name":"' .
                $name .
                '","type":"trojan","server":"' .
                $server .
                '","port":' .
                $port .
                ',"udp":false,"password":"' .
                $username .
                '"' .
                $sni .
                ',"skip-cert-verify":' .
                $skip_cert .
                ',"network":"tcp","client-fingerprint":"chrome"}';
            break;
        case "surfboard":
            $tr_template =
                $name .
                " = trojan, " .
                $server .
                ", " .
                $port .
                ", password = " .
                $username .
                ", udp-delay = true, skip-cert-verify = " .
                $skip_cert .
                ", sni = " .
                $sni .
                ", ws = false";
            break;
    }

    return $tr_template;
}

function process_shadowsocks_clash(array $decoded_config, $output_type)
{
    $name = $decoded_config["name"];
    if ($name === "" || $name === null) {
        return null;
    }
    $server = $decoded_config["server_address"];
    $port = $decoded_config["server_port"];
    $password = $decoded_config["password"];
    $cipher = $decoded_config["encryption_method"];
    switch ($output_type) {
        case "clash":
        case "meta":
            $ss_template =
                '  - {"name":"' .
                $name .
                '","type":"ss","server":"' .
                $server .
                '","port":' .
                $port .
                ',"password":"' .
                $password .
                '","cipher":"' .
                $cipher .
                '"}';
            break;
        case "surfboard":
            $ss_template =
                $name .
                " = ss, " .
                $server .
                ", " .
                $port .
                ", encrypt-method = " .
                $cipher .
                ", password = " .
                $password;
            break;
    }
    return $ss_template;
}

function is_valid_uuid($uuid_string) {
    $pattern = '/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/i';
    return (bool) preg_match($pattern, $uuid_string);
  }

function getPort(array $decoded_config) {
    return isset($decoded_config["port"]) && $decoded_config["port"] !== "" ? $decoded_config["port"] : 443;
}

function getSni(array $decoded_config) {
    return isset($decoded_config["params"]["sni"]) ? ',"servername":"' . $decoded_config["params"]["sni"] . '"' : "";
}

function getTls(array $decoded_config) {
    return isset($decoded_config["params"]["security"]) && $decoded_config["params"]["security"] === "tls" ? "true" : "false";
}

function getFlow(array $decoded_config) {
    return isset($decoded_config["params"]["flow"]) ? ',"flow":"xtls-rprx-vision"' : "";
}

function getNetwork(array $decoded_config) {
    return isset($decoded_config["params"]["type"]) ? $decoded_config["params"]["type"] : "tcp";
}

function getWsOpts(array $decoded_config) {
    if ($decoded_config["params"]["type"] !== "ws") {
        return "";
    }
    $path = isset($decoded_config["params"]["path"]) ? htmlentities($decoded_config["params"]["path"], ENT_QUOTES) : "/";
    $host = isset($decoded_config["params"]["host"]) ? ',"headers":{"host":"' .$decoded_config["params"]["host"] . '"}' : "";
    return ',"ws-opts":{"path":"' . $path . '"' . $host . '}';
}

function getGrpcOpts(array $decoded_config) {
    if ($decoded_config["params"]["type"] !== "grpc") {
        return "";
    }
    return isset($decoded_config["params"]["serviceName"]) ? ',"grpc-opts":{"grpc-service-name":"' . $decoded_config["params"]["serviceName"] . '"}' : "";
}

function getClientFingerprint(array $decoded_config) {
    if (!isset($decoded_config["params"]["fp"])) {
        return ',"client-fingerprint":"chrome"';
    }
    $fp = $decoded_config["params"]["fp"];
    if (in_array($fp, ["random", "ios", "android"])) {
        return ',"client-fingerprint":"chrome"';
    }
    return ',"client-fingerprint":"' . $fp . '"';
}

function getRealityOpts(array $decoded_config) {
    if (!isset($decoded_config["params"]["security"]) || $decoded_config["params"]["security"] !== "reality") {
        return "";
    }
    $pbk = $decoded_config["params"]["pbk"];
    $sid = isset($decoded_config["params"]["sid"]) && $decoded_config["params"]["sid"] !== "" ? ',"short-id":"' . $decoded_config["params"]["sid"] . '"' : "";
    $fingerprint = getClientFingerprint($decoded_config);
    return ',"reality-opts":{"public-key":"' . $pbk . '"' . $sid . $fingerprint . "}";
}

function getUsername(array $decoded_config){
    if (is_valid_uuid($decoded_config["username"]) === false){
        return null;
    }
    return $decoded_config["username"];
}

function process_vless_clash(array $decoded_config, $output_type) {
    $name = $decoded_config["hash"];
    if ($name === "") {
        return null;
    }
    $server = $decoded_config["hostname"];
    $port = getPort($decoded_config);
    $username = getUsername($decoded_config);
    if (is_null($username)){
        return null;
    }
    $sni = getSni($decoded_config);
    $tls = getTls($decoded_config);
    $flow = getFlow($decoded_config);
    $network = getNetwork($decoded_config);
    $opts = "";
    switch ($network) {
        case "ws":
            $opts = getWsOpts($decoded_config);
            break;
        case "grpc":
            $opts = getGrpcOpts($decoded_config);
            break;
    }
    $fingerprint = getClientFingerprint($decoded_config);
    $reality_opts = getRealityOpts($decoded_config);

    switch ($output_type) {
        case "meta":
            $vl_template =
                '  - {"name":"' .
                $name .
                '","type":"vless","server":"' .
                $server .
                '","port":' .
                $port .
                ',"udp":false,"uuid":"' .
                $username .
                '","tls":' .
                $tls .
                $sni .
                $flow .
                ',"network":"' .
                $network .
                '"' .
                $opts .
                $reality_opts .
                $fingerprint .
                "}";
            break;
        case "clash":
        case "surfboard":
            return null;
    }

    return str_replace(",,", ",", $vl_template);
}

function process_convert($config, $type, $output_type)
{
    switch ($type) {
        case "vmess":
            return process_vmess_clash($config, $output_type);
        case "vless":
            return process_vless_clash($config, $output_type);
        case "trojan":
            return process_trojan_clash($config, $output_type);
        case "ss":
            return process_shadowsocks_clash($config, $output_type);
    }
}

function generate_proxies($input, $output_type)
{
    $proxies = "";
    if (is_valid_address($input)) {
        if (is_base64_encoded(file_get_contents($input)) === "true") {
            $v2ray_subscription = base64_decode(
                file_get_contents($input),
                true
            );
        } else {
            $v2ray_subscription = file_get_contents($input);
        }
    } else {
        if (is_base64_encoded($input) === "true") {
            $v2ray_subscription = base64_decode($input, true);
        } else {
            $v2ray_subscription = $input;
        }
    }

    $configs_array = explode("\n", $v2ray_subscription);
    $suitable_config = suitable_output($configs_array, $output_type);
    foreach ($suitable_config as $config) {
        $type = detect_type($config);
        $decoded_config = parse_config($config, $type);
        $proxies .= !is_null(
            process_convert($decoded_config, $type, $output_type)
        )
            ? process_convert($decoded_config, $type, $output_type) . "\n"
            : null;
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
            unset($configs_array[0]);
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

function full_config($input, $type, $protocol = "mix")
{
    $surf_url = "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/surfboard/" . $protocol;

    $config_start = get_config_start($type, $surf_url);
    $config_proxy_group = get_config_proxy_group($type);
    $config_proxy_rules = get_config_proxy_rules($type);

    $proxies = generate_proxies($input, $type);
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
            "port: 7890",
            "socks-port: 7891",
            "allow-lan: true",
            "mode: Rule",
            "log-level: info",
            "ipv6: true",
            "external-controller: 0.0.0.0:9090",
        ],
        "meta" => [
            "port: 7890",
            "socks-port: 7891",
            "allow-lan: true",
            "mode: Rule",
            "log-level: info",
            "ipv6: true",
            "external-controller: 0.0.0.0:9090",
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
                    "    interval: 300",
                    "    tolerance: 50",
                    "    proxies:",
                ],
                "FALLBACK" => [
                    "  - name: FALLBACK",
                    "    type: fallback",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 300",
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
        "clash" => ["rules:", " - GEOIP,IR,DIRECT", " - MATCH,MANUAL"],
        "meta" => ["rules:", " - GEOIP,IR,DIRECT", " - MATCH,MANUAL"],
        "surfboard" => ["[Rule]", "GEOIP,IR,DIRECT", "FINAL,MANUAL"],
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
$type = filter_input(INPUT_GET, "type", FILTER_SANITIZE_STRING);
$process = filter_input(INPUT_GET, "process", FILTER_SANITIZE_STRING);
$protocol = filter_input(INPUT_GET, "protocol", FILTER_SANITIZE_STRING);
$type_array = ["clash", "meta", "surfboard"];

try {
    if (!$url) {
        throw new Exception("url parameter is missing or invalid");
    }

    if (!$type or !in_array($type, $type_array)) {
        throw new Exception("type parameter is missing or invalid");
    }

    if ($process === "name") {
        echo extract_names(generate_proxies($url, $type), $type);
    } elseif ($process === "full") {
        echo str_replace("\\", "", full_config($url, $type, isset($protocol) ? $protocol : "mix"));
    } else {
        echo generate_proxies($url, $type);
    }
} catch (Exception $e) {
    $output = [
        "ok" => false,
        "result" => $e->getMessage(),
    ];
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}
