<?php
/**
 * Extracts and unpacks P.A.S. Fork v. 1.4 webshells.
 * 
 * @param string $input_file
 */

$input_file = $argv[1];
if (!file_exists($input_file)) { 
    die("File not found!"); 
}
$raw_data = file_get_contents($input_file);

$type = 'DEFAULT';
if (preg_match('/^PK/', $raw_data)) { 
    $type = 'ZIP';
    echo ">> Zip detected\n";
}
elseif (preg_match('/__HALT_COMPILER\(\);/', $raw_data)) { 
    $type = 'PHAR'; 
    echo ">> Phar detected\n";
}

switch ($type) {
    case 'PHAR':
        $ext = pathinfo($input_file, PATHINFO_EXTENSION);
        if (strtolower($ext) !== 'phar') {
            rename($input_file, 'pas_phar.phar');
        }

        $temp_dir = 'pas_phar_extracted';
        mkdir($temp_dir);

        $pas_phar = new Phar('pas_phar.phar');
        $pas_phar->extractTo($temp_dir);

        foreach (scandir($temp_dir) as $file) {
            if ($file !== '.' && $file != '..') {
                $decompiled_shell = $temp_dir . DIRECTORY_SEPARATOR . 'decompiled.txt';
                rename($temp_dir . DIRECTORY_SEPARATOR . $file, $decompiled_shell);
                break;
            }
        }

        $shell_data = file_get_contents($decompiled_shell);
        $decoded_data = reverse_transformation($shell_data);
        file_put_contents('pas_shell_unpacked.php', $decoded_data);
        echo ">> Unpacked P.A.S. shell exported\n";
        break;

    case 'ZIP':
        $ext = pathinfo($input_file, PATHINFO_EXTENSION);
        if (strtolower($ext) !== 'zip') {
            rename($input_file, 'pas_zip.zip');
        }

        $temp_dir = 'pas_zip_extracted';
        mkdir($temp_dir);

        $zip = new ZipArchive;
        $res = $zip->open($input_file);
        if ($res === TRUE) {
            $zip->extractTo($temp_dir);
            $zip->close();
        }
        
        foreach (scandir($temp_dir) as $file) {
            if ($file !== '.' && $file !== '..') {
                $file_path = $temp_dir . DIRECTORY_SEPARATOR . $file;
                $unzipped_data = file_get_contents($file_path);

                if (preg_match('/[A-Za-z0-9+\/]{40,}/', $unzipped_data)) {
                    $unzipped_shell = $temp_dir . DIRECTORY_SEPARATOR . 'unzipped.txt';
                    rename($temp_dir . DIRECTORY_SEPARATOR . $file, $unzipped_shell);
                    $decoded_data = reverse_transformation($unzipped_data);
                    file_put_contents('pas_shell_unpacked.php', $decoded_data);
                    echo ">> Unpacked P.A.S. shell exported\n";
                    break;
                }
            }
        }
    
    default:
        $matches = extract_b64($input_file, 30);
        foreach ($matches as $i => $m) {
            //echo ($i + 1) . ": " . $m . "\n";
            file_put_contents('pas_shell_data.txt', $m . PHP_EOL, FILE_APPEND);
        }
        
        $shell_data = file_get_contents('pas_shell_data.txt');
        $decoded_data = reverse_default($shell_data);

        if ($decoded_data == false) {
            // If regex method fails, try token method
            $shell_data = remove_comments($input_file);
            $decoded_data = reverse_default($shell_data);
            file_put_contents('pas_shell_unpacked.php', $decoded_data);
            echo ">> Unpacked P.A.S. shell exported\n";
        } else {
            file_put_contents('pas_shell_unpacked.php', $decoded_data);
            echo ">> Unpacked P.A.S. shell exported\n";
        } 
}

// Routine that works for PHAR or ZIP 
function reverse_transformation($raw_data) {
    $raw_data = str_replace(["\r\n", "\n"], '', $raw_data);
    $raw_data = str_rot13($raw_data);
    $raw_data = base64_decode($raw_data);
    $raw_data = gzinflate($raw_data);
    return $raw_data;
}

// Routine for the default case
function reverse_default($raw_data) {
    $raw_data = str_replace(['.', '"', "\r\n", "\n"], '', $raw_data);
    $raw_data = str_rot13($raw_data);
    $raw_data = strrev($raw_data);
    $raw_data = base64_decode($raw_data);
    $raw_data = gzinflate($raw_data);
    return $raw_data;
}

function remove_comments(string $input_file) {
    $raw_data = file_get_contents($input_file);
    $tokens = token_get_all($raw_data);
    $output = '';

    foreach ($tokens as $token) {
        if (is_array($token)) {
            if (in_array($token[0], [T_COMMENT, T_DOC_COMMENT])) {
                continue;
            }
            $output .= $token[1];
        } else {
            // Add symbols (e.g., braces, semicolons) directly
            $output .= $token;
        }
    }
    return $output;
}

function extract_b64(string $input_file, int $min_len): array {
    $raw_data = file_get_contents($input_file);
    //$pattern = '/[A-Za-z0-9+\/]{' . $min_len . ',}(={0,2})/';
    $pattern = '/[A-Za-z0-9+\/]{40,}(?:={1,2})?/';
    preg_match_all($pattern, $raw_data, $matches);
    return $matches[0];
}
?>