 
<?php

// Replace with your Discord Bot Token (keep it secret)
$botToken = '0f8ab6334fbbe0ec9ee562fd5a43ea1e8a80e8b52cc7734037897ea3b09e9d39'; 

$payload = file_get_contents('php://input');
endpointVerify($_SERVER, $payload, $botToken);

function endpointVerify(array $headers, string $payload, string $publicKey)
{
    if (
        !isset($headers['HTTP_X_SIGNATURE_ED25519'])
        || !isset($headers['HTTP_X_SIGNATURE_TIMESTAMP'])
    )
        return ['code' => 401, 'payload' => null];

    $signature = $headers['HTTP_X_SIGNATURE_ED25519'];
    $timestamp = $headers['HTTP_X_SIGNATURE_TIMESTAMP'];

    if (!trim($signature, '0..9A..Fa..f') == '')
        return ['code' => 401, 'payload' => null];

    $message = $timestamp . $payload;
    $binarySignature = sodium_hex2bin($signature);
    $binaryKey = sodium_hex2bin($publicKey);

    if (!sodium_crypto_sign_verify_detached($binarySignature, $message, $binaryKey))
        return ['code' => 401, 'payload' => null];

    $payload = json_decode($payload, true);
    switch ($payload['type'])
    {
        // Verification
        case 1:
            $result = ['code' => 200, 'payload' => ['type' => 1]];
            http_response_code($result['code']);
            echo json_encode($result['payload']);
            break;

        // Bot messages
        case 2:
            $body = [
                'code' => 200, 
                'payload' => [
                    'type' => 5
                ]
            ];
            http_response_code($body['code']);
            echo json_encode($body['payload']);

            if ($payload["data"]["name"] == 'lfg')
            {
                $body = [
                    'code' => 200, 
                    'payload' => [
                        'type' => 4, 
                        'data' => [
                            "tts" => False,
                            "content" => "Message to test reply to discord",
                            "embeds" => [],
                            "allowed_mentions" => [
                                "parse" => []
                            ]
                        ]
                    ]
                ];
                http_response_code($body['code']);
                echo json_encode($body['payload']);
            }
            else
            {
                $result = ['code' => 200, 'payload' => ['type' => 2]];
                http_response_code($result['code']);
                echo json_encode($result['payload']);
                
            }
            break;

        default:
            $result = ['code' => 400, 'payload' => null];
            http_response_code($result['code']);
            echo json_encode($result['payload']);
    }
}

?>
