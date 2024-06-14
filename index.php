<?php

$public_key = "0f8ab6334fbbe0ec9ee562fd5a43ea1e8a80e8b52cc7734037897ea3b09e9d39";
$headers = getallheaders();
$signature = $headers["X-Signature-Ed25519"];
$timestamp = $headers["X-Signature-Timestamp"];
$body = file_get_contents('php://input');



public function authorize(array $headers, string $body, string $public_key): array
{
    $res = [
        'code' => 200,
        'payload' => []
    ];

    if (!isset($headers['x-signature-ed25519']) || !isset($headers['x-signature-timestamp'])) {
        $res['code'] = 401;
        return $res;
    }

    $signature = $headers['x-signature-ed25519'];
    $timestamp = $headers['x-signature-timestamp'];

    if (!trim($signature, '0..9A..Fa..f') == '') {
        $res['code'] = 401;
        return $res;
    }

    $message = $timestamp . $body;
    $binary_signature = sodium_hex2bin($signature);
    $binary_key = sodium_hex2bin($discord_public);

    if (!sodium_crypto_sign_verify_detached($binary_signature, $message, $binary_key)) {
        $res['code'] = 401;
        return $res;
    }

    $payload = json_decode($body, true);
    switch ($payload['type']) {
        case 1:
            $res['payload']['type'] = 1;
            break;

        case 2:
            $res['payload']['type'] = 2;
            break;

        default:
            $res['code'] = 400;
            return $res;
    }

    return $res;
}

authorize(array $headers, string $body, string $public_key);
