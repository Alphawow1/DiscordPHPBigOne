<?php

// Your Discord application's public key
$publicKey = '0f8ab6334fbbe0ec9ee562fd5a43ea1e8a80e8b52cc7734037897ea3b09e9d39';

// Get the raw HTTP payload
$payload = file_get_contents('php://input');

// Get all headers
$headers = getallheaders();

// Log incoming headers and payload for debugging
file_put_contents('log.txt', "Headers:\n" . print_r($headers, true), FILE_APPEND);
file_put_contents('log.txt', "Payload:\n" . $payload . "\n", FILE_APPEND);

// Verify the endpoint
$result = verifyDiscordSignature($headers, $payload, $publicKey);

// Send the appropriate HTTP response code
http_response_code($result['code']);
echo json_encode($result['payload']);

function verifyDiscordSignature(array $headers, string $payload, string $publicKey): array
{
    // Ensure the necessary headers are present
    if (!isset($headers['X-Signature-Ed25519']) || !isset($headers['X-Signature-Timestamp'])) {
        file_put_contents('log.txt', "Missing signature or timestamp header\n", FILE_APPEND);
        return ['code' => 401, 'payload' => ['error' => 'Missing signature or timestamp header']];
    }

    $signature = $headers['X-Signature-Ed25519'];
    $timestamp = $headers['X-Signature-Timestamp'];

    // Validate the signature format
    if (!ctype_xdigit($signature)) {
        file_put_contents('log.txt', "Invalid signature format\n", FILE_APPEND);
        return ['code' => 401, 'payload' => ['error' => 'Invalid signature format']];
    }

    $message = $timestamp . $payload;
    file_put_contents('log.txt', "Message:\n" . $message . "\n", FILE_APPEND);

    try {
        $binarySignature = sodium_hex2bin($signature);
        $binaryKey = sodium_hex2bin($publicKey);
    } catch (Exception $e) {
        file_put_contents('log.txt', "Error converting hex to binary: " . $e->getMessage() . "\n", FILE_APPEND);
        return ['code' => 401, 'payload' => ['error' => 'Error converting hex to binary']];
    }

    // Verify the signature
    if (!sodium_crypto_sign_verify_detached($binarySignature, $message, $binaryKey)) {
        file_put_contents('log.txt', "Signature verification failed\n", FILE_APPEND);
        return ['code' => 401, 'payload' => ['error' => 'Signature verification failed']];
    }

    // Decode the payload
    $payload = json_decode($payload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        file_put_contents('log.txt', "JSON decode error: " . json_last_error_msg() . "\n", FILE_APPEND);
        return ['code' => 400, 'payload' => ['error' => 'JSON decode error']];
    }

    // Handle different payload types
    switch ($payload['type']) {
        case 1: // PING
            return ['code' => 200, 'payload' => ['type' => 1]];
        case 2: // APPLICATION_COMMAND
            // Handle your command logic here
            return ['code' => 200, 'payload' => ['type' => 2]];
        default:
            return ['code' => 400, 'payload' => ['error' => 'Invalid payload type']];
    }
}

?>
