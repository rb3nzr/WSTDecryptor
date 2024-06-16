<?php 

$shell = $argv[1];

try {
    $phar = new Phar($shell);
    $phar->extractTo(__DIR__ . '/../output/weevely_shells');
    $contents = file_get_contents(__DIR__. '/../output/weevely_shells/x');

    $data = [];

    if (preg_match('/\$k="([^"]+)";/', $contents, $matches)) {
        $data['k'] = $matches[1];
    } else {
        $data['k'] = '[no match]';
    }
    
    if (preg_match('/\$kh="([^"]+)";/', $contents, $matches)) {
        $data['kh'] = $matches[1];
    } else {
        $data['kh'] = '[no match]';
    }
    
    if (preg_match('/\$kf="([^"]+)";/', $contents, $matches)) {
        $data['kf'] = $matches[1];
    } else {
        $data['kf'] = '[no match]';
    }
    
    if (preg_match('/\$p="([^"]+)";/', $contents, $matches)) {
        $data['p'] = $matches[1];
    } else {
        $data['p'] = '[no match]';
    }

    echo json_encode($data);

} catch (Exception $err) {
    echo json_encode(['Error' => $err->getMessage()]);
}
?>