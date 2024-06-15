 
<?php

// Replace with your Discord Bot Token (keep it secret)
$botToken = '0f8ab6334fbbe0ec9ee562fd5a43ea1e8a80e8b52cc7734037897ea3b09e9d39';

// Get request data (replace with actual method for security)
$rawData = file_get_contents('php://input');

// Verify request (security is crucial!)
if (!verifyRequest($rawData)) {
  http_response_code(401);
  exit;
}

// Decode the JSON data
$data = json_decode($rawData, true);

// Handle the interaction based on type
if (isset($data['type']) && $data['type'] === 1) {
  // It's a Slash Command interaction
  handleSlashCommand($data);
} else {
  // Handle other interaction types (optional)
  http_response_code(400); // Bad request
  exit;
}


// Function to verify the request (replace with actual verification logic)
function verifyRequest($data) {
  // This is a placeholder, implement proper signature verification using Discord's headers
  // You'll need to retrieve the public key from your Discord application settings
  // Refer to Discord's documentation for secure verification: https://discord.com/developers/docs/interactions/receiving-and-responding

  return true; // Placeholder, replace with actual verification logic
}

// Function to handle Slash Commands (replace with your command logic)
function handleSlashCommand($data) {
  $command = $data['data']['name'];
  $channelId = $data['channel_id'];

  $response = [
    "type" => 4,
    "data" => [
      "content" => "This is a response to the command: $command"
    ]
  ];

  sendResponse($response);
}

// Function to send a response to Discord (replace with actual sending logic)
function sendResponse($data) {
  $url = "https://discord.com/api/interactions/" . $data['interaction']['id'] . "/" . $data['interaction']['token'] . "/callback";
  $headers = array(
    "Content-Type: application/json",
    "Authorization: Bot $botToken"
  );

  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

  $response = curl_exec($ch);
  $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

  curl_close($ch);

  if ($httpCode !== 200) {
    // Handle sending error
    echo "Failed to send response, code: $httpCode";
  }
}

?>
