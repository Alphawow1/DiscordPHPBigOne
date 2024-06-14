<?php

$payload = file_get_contents('php://input');
$headers = getallheaders();
$result = endpointVerify($headers, $payload, '0f8ab6334fbbe0ec9ee562fd5a43ea1e8a80e8b52cc7734037897ea3b09e9d39');
http_response_code($result['code']);
echo json_encode($result['payload']);

function endpointVerify(array $headers, string $payload, string $publicKey): array
{
    if (
        !isset($headers['X-Signature-Ed25519'])
        || !isset($headers['X-Signature-Timestamp'])
    )
        return ['code' => 401, 'payload' => null];

    $signature = $headers['X-Signature-Ed25519'];
    $timestamp = $headers['X-Signature-Timestamp'];

    if (!ctype_xdigit($signature))
        return ['code' => 401, 'payload' => null];

    $message = $timestamp . $payload;
    $binarySignature = sodium_hex2bin($signature);
    $binaryKey = sodium_hex2bin($publicKey);

    if (!sodium_crypto_sign_verify_detached($binarySignature, $message, $binaryKey))
        return ['code' => 401, 'payload' => null];

    $payload = json_decode($payload, true);
    switch ($payload['type']) {
        case 1:
            return ['code' => 200, 'payload' => ['type' => 1]];
        case 2:
            return ['code' => 200, 'payload' => ['type' => 2]];
        default:
            return ['code' => 400, 'payload' => null];
    }
}

?>
