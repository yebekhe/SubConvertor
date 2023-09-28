<?php

/** Detect Type of Config */
function detect_type($input)
{
    $type = "";
    if (substr($input, 0, 8) === "vmess://") {
        $type = "vmess";
    } elseif (substr($input, 0, 8) === "vless://") {
        $type = "vless";
    } elseif (substr($input, 0, 9) === "trojan://") {
        $type = "trojan";
    } elseif (substr($input, 0, 5) === "ss://") {
        $type = "ss";
    }

    return $type;
}

function parse_config($input, $type)
{
    $type = detect_type($input);
    $parsed_config = [];
    switch ($type) {
        case "vmess":
            $parsed_config = decode_vmess($input);
            break;
        case "vless":
        case "trojan":
            $parsed_config = parseProxyUrl($input, $type);
            break;
        case "ss":
            $parsed_config = ParseShadowsocks($input);
            break;
    }
    return $parsed_config;
}


/** parse vmess configs */
function decode_vmess($vmess_config)
{
    $vmess_data = substr($vmess_config, 8); // remove "vmess://"
    $decoded_data = json_decode(base64_decode($vmess_data), true);
    return $decoded_data;
}

/** Parse vless and trojan config*/
function parseProxyUrl($url, $type = "trojan")
{
    // Parse the URL into components
    $parsedUrl = parse_url($url);

    // Extract the parameters from the query string
    $params = [];
    if (isset($parsedUrl["query"])) {
        parse_str($parsedUrl["query"], $params);
    }

    // Construct the output object
    $output = [
        "protocol" => $type,
        "username" => isset($parsedUrl["user"]) ? $parsedUrl["user"] : "",
        "hostname" => isset($parsedUrl["host"]) ? $parsedUrl["host"] : "",
        "port" => isset($parsedUrl["port"]) ? $parsedUrl["port"] : "",
        "params" => $params,
        "hash" => isset($parsedUrl["fragment"]) ? $parsedUrl["fragment"] : "",
    ];

    return $output;
}
/** parse shadowsocks configs */
function ParseShadowsocks($config_str)
{
    // Parse the config string as a URL
    $url = parse_url($config_str);

    // Extract the encryption method and password from the user info
    list($encryption_method, $password) = explode(
        ":",
        base64_decode($url["user"])
    );

    // Extract the server address and port from the host and path
    $server_address = $url["host"];
    $server_port = $url["port"];

    // Extract the name from the fragment (if present)
    $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : null;

    // Create an array to hold the server configuration
    $server = [
        "encryption_method" => $encryption_method,
        "password" => $password,
        "server_address" => $server_address,
        "server_port" => $server_port,
        "name" => $name,
    ];

    // Return the server configuration as a JSON string
    return $server;
}


function is_number_with_dots($s)
{
    /*
     * Returns true if the given string contains only digits and dots, and false otherwise.
     */
    for ($i = 0; $i < strlen($s); $i++) {
        $c = $s[$i];
        if (!ctype_digit($c) && $c != ".") {
            return false;
        }
    }
    return true;
}

function is_valid_address($address)
{
    $ipv4_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    $ipv6_pattern = '/^[0-9a-fA-F:]+$/'; // matches any valid IPv6 address

    if (
        preg_match($ipv4_pattern, $address) ||
        preg_match($ipv6_pattern, $address)
    ) {
        return true;
    } elseif (is_number_with_dots($address) === false) {
        if (
            substr($address, 0, 8) === "https://" ||
            substr($address, 0, 7) === "http://"
        ) {
            $url = filter_var($address, FILTER_VALIDATE_URL);
        } else {
            $url = filter_var("https://" . $address, FILTER_VALIDATE_URL);
        }
        if ($url !== false) {
            return true;
        } else {
            return false;
        }
    }
    return false;
}

function numberToEmoji($number) {
    $map = array(
        '0' => '0️⃣',
        '1' => '1️⃣',
        '2' => '2️⃣',
        '3' => '3️⃣',
        '4' => '4️⃣',
        '5' => '5️⃣',
        '6' => '6️⃣',
        '7' => '7️⃣',
        '8' => '8️⃣',
        '9' => '9️⃣'
    );
    
    $emoji = "";
    $digits = str_split($number);
    
    foreach ($digits as $digit) {
        if (count($digits) === 1) {
            $emoji = $map['0'];
        }
        if (isset($map[$digit])) {
            $emoji .= $map[$digit];
        }
    }
    
    return $emoji;
}
