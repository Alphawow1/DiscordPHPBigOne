<?php
require_once 'DiscordInteraction.php';

use Discord\Interaction;
use Discord\InteractionResponseType;

$CLIENT_PUBLIC_KEY = getenv('0f8ab6334fbbe0ec9ee562fd5a43ea1e8a80e8b52cc7734037897ea3b09e9d39');

$signature = $_SERVER['HTTP_X_SIGNATURE_ED25519'];
$timestamp = $_SERVER['HTTP_X_SIGNATURE_TIMESTAMP'];
$postData = file_get_contents('php://input');

if (Interaction::verifyKey($postData, $signature, $timestamp, $CLIENT_PUBLIC_KEY)) {
  echo json_encode(array(
    'type' => InteractionResponseType::PONG
  ));
} else {
  http_response_code(401);
  echo "Not verified";
}
