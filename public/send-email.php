<?php
// Headers para respuesta JSON y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Permitir solicitudes OPTIONS (preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Solo aceptar POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Obtener entradas del cliente (JSON o formulario)
$rawInput = file_get_contents('php://input');
$data = null;
if ($rawInput !== '') {
    $data = json_decode($rawInput, true);
}
$firstName = '';
$lastName = '';
$name = '';
$email = '';
$phone = '';
$message = '';
$updatesConsent = false;
$language = 'es';
$brandName = 'Señor Taxes';
$brandEmail = 'pedro@agentesocial.com';
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? '');
$logoUrl = $host !== '' ? "{$scheme}://{$host}/logo.png" : 'https://elsenordelostaxes.com/logo.png';
if (is_array($data)) {
    $firstName = isset($data['firstName']) ? trim($data['firstName']) : '';
    $lastName = isset($data['lastName']) ? trim($data['lastName']) : '';
    $name = isset($data['name']) ? trim($data['name']) : '';
    $email = isset($data['email']) ? trim($data['email']) : '';
    $phone = isset($data['phone']) ? trim($data['phone']) : '';
    $message = isset($data['message']) ? trim($data['message']) : '';
    $updatesConsent = isset($data['updatesConsent']) ? (bool)$data['updatesConsent'] : false;
    $language = isset($data['language']) ? trim($data['language']) : $language;
} else {
    $firstName = isset($_POST['firstName']) ? trim($_POST['firstName']) : '';
    $lastName = isset($_POST['lastName']) ? trim($_POST['lastName']) : '';
    $name = isset($_POST['name']) ? trim($_POST['name']) : '';
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    $phone = isset($_POST['phone']) ? trim($_POST['phone']) : '';
    $message = isset($_POST['message']) ? trim($_POST['message']) : '';
    $updatesConsent = isset($_POST['updatesConsent']) ? filter_var($_POST['updatesConsent'], FILTER_VALIDATE_BOOLEAN) : false;
    $language = isset($_POST['language']) ? trim($_POST['language']) : $language;
}
// Sanitizar valores
$firstName = htmlspecialchars($firstName, ENT_QUOTES, 'UTF-8');
$lastName = htmlspecialchars($lastName, ENT_QUOTES, 'UTF-8');
$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$email = filter_var($email, FILTER_SANITIZE_EMAIL);
$phone = preg_replace('/[^0-9+\-\s\(\)]/', '', $phone);
$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

$fullName = trim($name !== '' ? $name : trim($firstName . ' ' . $lastName));

if (!$fullName || !$phone) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing required fields']);
    exit;
}

if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $email = '';
}

$submissionDate = gmdate('m/d/Y H:i:s');
$updatesLabel = $language === 'es' ? 'Acepta actualizaciones' : 'Updates consent';
$updatesValue = $updatesConsent ? ($language === 'es' ? 'Sí' : 'Yes') : ($language === 'es' ? 'No' : 'No');

$smtpHost = getenv('SMTP_HOST') ?: '';
$smtpPort = getenv('SMTP_PORT') ?: '';
$smtpUser = getenv('SMTP_USER') ?: '';
$smtpPass = getenv('SMTP_PASS') ?: '';
$smtpSecure = getenv('SMTP_SECURE') ?: 'tls';
$smtpFrom = getenv('SMTP_FROM') ?: 'noreply@elsenordelostaxes.com';
$smtpFromName = getenv('SMTP_FROM_NAME') ?: $brandName;
$useSmtp = $smtpHost !== '' && $smtpUser !== '' && $smtpPass !== '';

function smtpRead($connection) {
    $data = '';
    while (!feof($connection)) {
        $line = fgets($connection, 515);
        if ($line === false) {
            break;
        }
        $data .= $line;
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    return $data;
}

function smtpWrite($connection, $command) {
    fwrite($connection, $command . "\r\n");
    return smtpRead($connection);
}

function smtpSend($config, $toEmail, $subject, $htmlBody, $replyTo = '') {
    $host = $config['host'];
    $port = (int)($config['port'] ?: 587);
    $user = $config['user'];
    $pass = $config['pass'];
    $secure = $config['secure'];
    $fromEmail = $config['fromEmail'];
    $fromName = $config['fromName'];
    $serverName = $_SERVER['SERVER_NAME'] ?? 'localhost';

    $transportHost = $secure === 'ssl' ? "ssl://{$host}" : $host;
    $connection = stream_socket_client("{$transportHost}:{$port}", $errno, $errstr, 12);
    if (!$connection) {
        return ['ok' => false, 'error' => $errstr ?: 'SMTP connection failed'];
    }

    $response = smtpRead($connection);
    if (!preg_match('/^220/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }

    $response = smtpWrite($connection, "EHLO {$serverName}");
    if (!preg_match('/^250/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }

    if ($secure === 'tls') {
        $response = smtpWrite($connection, "STARTTLS");
        if (!preg_match('/^220/', $response)) {
            fclose($connection);
            return ['ok' => false, 'error' => trim($response)];
        }
        if (!stream_socket_enable_crypto($connection, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            fclose($connection);
            return ['ok' => false, 'error' => 'TLS negotiation failed'];
        }
        $response = smtpWrite($connection, "EHLO {$serverName}");
        if (!preg_match('/^250/', $response)) {
            fclose($connection);
            return ['ok' => false, 'error' => trim($response)];
        }
    }

    $response = smtpWrite($connection, "AUTH LOGIN");
    if (!preg_match('/^334/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }
    $response = smtpWrite($connection, base64_encode($user));
    if (!preg_match('/^334/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }
    $response = smtpWrite($connection, base64_encode($pass));
    if (!preg_match('/^235/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }

    $response = smtpWrite($connection, "MAIL FROM:<{$fromEmail}>");
    if (!preg_match('/^250/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }

    $response = smtpWrite($connection, "RCPT TO:<{$toEmail}>");
    if (!preg_match('/^250/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }

    $response = smtpWrite($connection, "DATA");
    if (!preg_match('/^354/', $response)) {
        fclose($connection);
        return ['ok' => false, 'error' => trim($response)];
    }

    $encodedSubject = function_exists('mb_encode_mimeheader')
        ? mb_encode_mimeheader($subject, 'UTF-8')
        : $subject;
    $encodedFromName = function_exists('mb_encode_mimeheader')
        ? mb_encode_mimeheader($fromName, 'UTF-8')
        : $fromName;
    $headers = [];
    $headers[] = "From: {$encodedFromName} <{$fromEmail}>";
    $headers[] = "To: <{$toEmail}>";
    $headers[] = "Subject: {$encodedSubject}";
    $headers[] = "MIME-Version: 1.0";
    $headers[] = "Content-Type: text/html; charset=UTF-8";
    if ($replyTo !== '') {
        $headers[] = "Reply-To: {$replyTo}";
    }
    $data = implode("\r\n", $headers) . "\r\n\r\n" . $htmlBody . "\r\n.";
    $response = smtpWrite($connection, $data);
    smtpWrite($connection, "QUIT");
    fclose($connection);

    if (!preg_match('/^250/', $response)) {
        return ['ok' => false, 'error' => trim($response)];
    }
    return ['ok' => true, 'error' => ''];
}

// Crear contenido HTML del email
$companyTexts = [
    'en' => [
        'title' => 'New Contact Message',
        'intro' => "You have received a new message from the {$brandName} website. Below are the details:",
        'name_label' => 'Full name',
        'phone_label' => 'Phone',
        'message_label' => 'Message',
        'email_label' => 'Email',
        'submission_label' => 'Submission Date'
    ],
    'es' => [
        'title' => 'Nuevo mensaje de contacto',
        'intro' => "Has recibido un nuevo mensaje desde el sitio {$brandName}. A continuación los detalles:",
        'name_label' => 'Nombre completo',
        'phone_label' => 'Teléfono',
        'message_label' => 'Mensaje',
        'email_label' => 'Email',
        'submission_label' => 'Fecha de envío'
    ]
];
$ct = $companyTexts[$language] ?? $companyTexts['es'];

$optEmailSection = $email !== '' ? <<<EMAIL_HTML
            <div class="section">
                <div class="section-title">{$ct['email_label']}</div>
                <div class="section-value"><a href="mailto:{$email}">{$email}</a></div>
            </div>
EMAIL_HTML : '';
$optMessageSection = $message !== '' ? <<<MSG_HTML
            <div class="section">
                <div class="section-title">{$ct['message_label']}</div>
                <div class="section-value">{$message}</div>
            </div>
MSG_HTML : '';
$updatesSection = <<<UPDATES_HTML
            <div class="section">
                <div class="section-title">{$updatesLabel}</div>
                <div class="section-value">{$updatesValue}</div>
            </div>
UPDATES_HTML;

$emailContent = <<<HTML
<!DOCTYPE html>
<html lang="{$language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }
        .header img {
            max-width: 300px;
            height: auto;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section-title {
            font-size: 14px;
            font-weight: 700;
            color: #111827;
            text-transform: uppercase;
            margin-bottom: 8px;
            letter-spacing: 1px;
        }
        .section-value {
            font-size: 16px;
            color: #333;
            line-height: 1.6;
            word-break: break-word;
        }
        .divider {
            border: none;
            border-top: 1px solid #e0e0e0;
            margin: 30px 0;
        }
        .footer {
            background-color: #f9f9f9;
            padding: 30px 40px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
        }
        .footer p {
            margin: 0;
            font-size: 12px;
            color: #999;
            line-height: 1.6;
        }
        .footer a {
            color: #111827;
            text-decoration: none;
        }
        .cta-button {
            display: inline-block;
            background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
            color: white;
            padding: 12px 30px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="{$logoUrl}" alt="{$brandName}">
            <h1>{$ct['title']}</h1>
        </div>
        
        <div class="content">
            <p style="font-size: 16px; color: #333; margin-top: 0;">{$ct['intro']}</p>
            
            <hr class="divider">
            
            <div class="section">
                <div class="section-title">{$ct['name_label']}</div>
                <div class="section-value">{$fullName}</div>
            </div>

            {$optEmailSection}
            <div class="section">
                <div class="section-title">{$ct['phone_label']}</div>
                <div class="section-value"><a href="tel:{$phone}">{$phone}</a></div>
            </div>
            {$optMessageSection}
            {$updatesSection}
            
            <hr class="divider">
            
            <p style="font-size: 14px; color: #999; margin: 0;">
                <strong>{$ct['submission_label']}:</strong> {$submissionDate} (UTC)
            </p>
        </div>
        
        <div class="footer">
            <p>
                Este correo fue generado automáticamente desde tu sitio.<br>
                <strong>{$brandName}</strong><br>
                <a href="mailto:{$brandEmail}">{$brandEmail}</a>
            </p>
        </div>
    </div>
</body>
</html>
HTML;

// Destinatario y asunto del email
$toCompany = $brandEmail;
$subjectCompany = $language === 'es' ? "Nuevo mensaje de contacto - {$brandName}" : "New contact message - {$brandName}";

// Configurar headers para enviar email en HTML
$headers = "MIME-Version: 1.0\r\n";
$headers .= "Content-type: text/html; charset=UTF-8\r\n";
$headers .= "From: {$smtpFrom}\r\n";
$emailHeader = preg_replace("/\r|\n/", "", $email);
if ($emailHeader !== '') {
    $headers .= "Reply-To: {$emailHeader}\r\n";
}

$mailToCompany = false;
$companyError = '';
$deliveryMethod = 'mail';
if ($useSmtp) {
    $deliveryMethod = 'smtp';
    $smtpResult = smtpSend([
        'host' => $smtpHost,
        'port' => $smtpPort,
        'user' => $smtpUser,
        'pass' => $smtpPass,
        'secure' => $smtpSecure,
        'fromEmail' => $smtpFrom,
        'fromName' => $smtpFromName
    ], $toCompany, $subjectCompany, $emailContent, $emailHeader);
    $mailToCompany = $smtpResult['ok'];
    $companyError = $smtpResult['error'];
} else {
    if (!function_exists('mail')) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'mail() not available on server']);
        exit;
    }
    $mailToCompany = mail($toCompany, $subjectCompany, $emailContent, $headers);
}

// Definir textos del email del cliente según idioma
$clientTexts = [
    'en' => [
        'title' => 'Submission Confirmed',
        'greeting' => 'Hello',
        'success' => '✓ Your message has been received successfully. Our team will contact you soon.',
        'thankYou' => "Thank you for contacting {$brandName}. We will be in touch soon.",
        'info_title' => 'Your Information',
        'info_name' => 'Name',
        'info_email' => 'Email',
        'info_phone' => 'Phone',
        'info_message' => 'Your Message',
        'info_updates' => 'Updates consent',
        'contact_text' => 'If you have any questions, write to',
    ],
    'es' => [
        'title' => 'Envío Confirmado',
        'greeting' => 'Hola',
        'success' => '✓ Tu mensaje ha sido recibido exitosamente. Nuestro equipo se pondrá en contacto contigo pronto.',
        'thankYou' => "Gracias por contactar a {$brandName}. Pronto nos comunicaremos contigo.",
        'info_title' => 'Tu Información',
        'info_name' => 'Nombre',
        'info_email' => 'Email',
        'info_phone' => 'Teléfono',
        'info_message' => 'Tu Mensaje',
        'info_updates' => 'Acepta actualizaciones',
        'contact_text' => 'Si tienes preguntas, escríbenos a',
    ]
];

$texts = $clientTexts[$language] ?? $clientTexts['en'];

$optClientEmailSection = $email !== '' ? <<<CLIENT_EMAIL
            <div class="info-section">
                <div class="info-label">{$texts['info_email']}</div>
                <div class="info-value">{$email}</div>
            </div>
CLIENT_EMAIL : '';
$optClientMessageSection = $message !== '' ? <<<CLIENT_MESSAGE
            <div class="info-section">
                <div class="info-label">{$texts['info_message']}</div>
                <div class="info-value">{$message}</div>
            </div>
CLIENT_MESSAGE : '';
$optClientUpdatesSection = <<<CLIENT_UPDATES
            <div class="info-section">
                <div class="info-label">{$texts['info_updates']}</div>
                <div class="info-value">{$updatesValue}</div>
            </div>
CLIENT_UPDATES;

// Crear email de confirmación para el cliente
$clientEmailContent = <<<CLIENT_HTML
<!DOCTYPE html>
<html lang="{$language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }
        .header img {
            max-width: 150px;
            height: auto;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }
        .content {
            padding: 40px;
        }
        .success-message {
            background-color: #f0fdf4;
            border-left: 4px solid #111827;
            padding: 20px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .success-message p {
            margin: 0;
            color: #22863a;
            font-size: 16px;
            line-height: 1.6;
        }
        .info-section {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .info-label {
            font-size: 12px;
            font-weight: 700;
            color: #111827;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        .info-value {
            font-size: 16px;
            color: #333;
        }
        .footer {
            background-color: #f9f9f9;
            padding: 30px 40px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
        }
        .footer p {
            margin: 0;
            font-size: 12px;
            color: #999;
            line-height: 1.6;
        }
        .footer a {
            color: #111827;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="{$logoUrl}" alt="{$brandName}">
            <h1>{$texts['title']}</h1>
        </div>
        
        <div class="content">
            <p style="font-size: 16px; color: #333; margin-top: 0;">{$texts['greeting']} {$fullName},</p>
            
            <div class="success-message">
                <p>{$texts['success']}</p>
            </div>
            
            <p style="font-size: 14px; color: #666; margin-top: 20px; line-height: 1.6;">
                {$texts['thankYou']}
            </p>
            
            <h3 style="color: #111827; margin-top: 30px;">{$texts['info_title']}</h3>
            
            <div class="info-section">
                <div class="info-label">{$texts['info_name']}</div>
                <div class="info-value">{$fullName}</div>
            </div>
            
            {$optClientEmailSection}
            <div class="info-section">
                <div class="info-label">{$texts['info_phone']}</div>
                <div class="info-value">{$phone}</div>
            </div>
            
            {$optClientMessageSection}
            {$optClientUpdatesSection}
            
            <p style="font-size: 14px; color: #666; margin-top: 30px; line-height: 1.6;">
                {$texts['contact_text']} <a href="mailto:{$brandEmail}">{$brandEmail}</a>
            </p>
        </div>
        
        <div class="footer">
            <p>
                <strong>{$brandName}</strong><br>
                <a href="mailto:{$brandEmail}">{$brandEmail}</a>
            </p>
        </div>
    </div>
</body>
</html>
CLIENT_HTML;

// Configurar headers para email del cliente
$clientHeaders = "MIME-Version: 1.0\r\n";
$clientHeaders .= "Content-type: text/html; charset=UTF-8\r\n";
$clientHeaders .= "From: {$smtpFrom}\r\n";

// Enviar email de confirmación al cliente
$clientSubject = $language === 'es' ? "Confirmación de envío - {$brandName}" : "Form Submission Confirmed - {$brandName}";
$mailToClient = null;
if ($email !== '') {
    $mailToClient = mail($email, $clientSubject, $clientEmailContent, $clientHeaders);
}

// Responder al cliente si se envió correctamente
if ($mailToCompany) {
    http_response_code(200);
    echo json_encode(['success' => true, 'message' => 'Email sent successfully', 'client_sent' => $mailToClient ? true : false, 'delivery' => $deliveryMethod]);
} else {
    http_response_code(500);
    $lastError = error_get_last();
    $errorDetail = $lastError && isset($lastError['message']) ? $lastError['message'] : '';
    $detail = $companyError !== '' ? $companyError : $errorDetail;
    echo json_encode(['success' => false, 'message' => 'Failed to send email to company', 'detail' => $detail, 'client_sent' => $mailToClient ? true : false, 'delivery' => $deliveryMethod]);
}
exit;
?>
