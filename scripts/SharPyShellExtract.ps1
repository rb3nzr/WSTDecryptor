<#
.DESCRIPTION 
    Attempts to find and extract: 
        - shellcode and related thread parameters: decode, decompress and recreate the output_func_byte variable. 
        - large byte arrays (module chunks): decrypt them.
        - smaller base64 blocks: decode them.
    Writes these out to .bin files in the $outputDirectory.
    Not foolproof, just a quick script to grab some of this stuff and save some time. 
    Will need to go through the output.cs file and compare files based on file counter number.
.PARAMETER InputFile 
    The decrypted runtime code output file produced from WSTDecryptor.py sharpyshell.
.PARAMETER OutputDirectory
    The temp directory for storing the module and shellcode files.
.PARAMETER Key
    The same key found inside the SharPyShell .aspx webshell.
.EXAMPLE
    ./ExtractModules.ps1 ./sharpy_output_20240613_190950.cs "/dir/path" "b0a20cddba121012871430edcf07976f94ced4ef0b0ea65b41bb060464e767d7"
    python WSTDecryptor.py sharpyshell -p sample.pcap -i x.x.x.x -k '<key>' --extract
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$True)]
    [String]$inputFile,  
    [Parameter(Position=1, Mandatory=$True)]
    [String]$outputDirectory,
    [Parameter(Position=2, Mandatory=$True)]
    [String]$key
)

function DecompressSC([byte[]]$data) {
    $compressedStream = New-Object System.IO.MemoryStream
    $compressedStream.Write($data, 0, $data.Length)
    $compressedStream.Seek(0, [System.IO.SeekOrigin]::Begin)
    $zipStream = New-Object System.IO.Compression.GZipStream($compressedStream, [System.IO.Compression.CompressionMode]::Decompress)
    $resultStream = New-Object System.IO.MemoryStream

    $bufferSize = 16 * 1024
    $buffer = New-Object byte[] $bufferSize
    $read = 0
    while (($read = $zipStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $resultStream.Write($buffer, 0, $read)
    }

    return $resultStream.ToArray()
}

if (-Not (Test-Path -Path $outputDirectory)) {
    Write-Host ">> Creating output directory: $outputDirectory" -ForegroundColor Green
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
} else {
    Write-Host ">> Output directory already exists: $outputDirectory" -ForegroundColor Yellow
}

$encKey = [System.Text.Encoding]::UTF8.GetBytes($key)
$fileContent = Get-Content -Path $inputFile -Raw
Write-Host ">> Read input file: $inputFile" -ForegroundColor Green


# Module chunks
$fileCounter = 0 
$byteArrayMatches = [regex]::Matches($fileContent, "byte\[\] file_bytes = \{([^\}]*)\}")
Write-Host ">> Found $($byteArrayMatches.Count) byte array matches" -ForegroundColor Green

foreach ($match in $byteArrayMatches) {
    try {
        $byteArrayString = $match.Groups[1].Value.Trim() -replace '\s+', ','
        $byteArray = $byteArrayString -split ',' | ForEach-Object { [Convert]::ToByte($_, 16) }

        $nonEncBinOutput = Join-Path -Path $outputDirectory -ChildPath ("unk_bin_{0}.bin" -f $fileCounter)
        [System.IO.File]::WriteAllBytes($nonEncBinOutput, $byteArray)
        Write-Host ">> Wrote possible unencrypted binary to: $outputFile" -ForegroundColor Green
        
        $decrypted = New-Object Byte[] $byteArray.Length 
        for ($i = 0; $i -lt $byteArray.Length; $i++) {
            $decrypted[$i] = $byteArray[$i] -bxor $key[$i % $key.Length]
        }

        $outputFile = Join-Path -Path $outputDirectory -ChildPath ("decrypted_module_{0}.bin" -f $fileCounter)
        [System.IO.File]::WriteAllBytes($outputFile, $decrypted)

        Write-Host ">> Wrote possible decrypted module chunk to: $outputFile" -ForegroundColor Green
        $fileCounter++
    } catch {
        continue 
    }
} 

# Find shellcode
$fileCounter2 = 0
$shellcodeMatches = [regex]::Matches($fileContent, 'shellcodeBase64\s*=\s*".+?"')
Write-Host ">> Found $($shellcodeMatches.Count) shellcode matches" -ForegroundColor Green

foreach ($match in $shellcodeMatches) {
    if ($match.Value) {
        try {
            if ($match.Value.Length -lt 200) {
                continue 
            }

            $blob = $match.Value -Replace 'shellcodeBase64 = "', '' -Replace '"$', ''
            $compressed = [System.Convert]::FromBase64String($blob)
            $decompressed = DecompressSC($compressed)

            $outputFile = Join-Path -Path $outputDirectory -ChildPath ("sc_{0}.bin" -f $fileCounter2)
            [System.IO.File]::WriteAllBytes($outputFile, $decompressed)

            Write-Host ">> Wrote decompressed shellcode to: $outputFile" -ForegroundColor Green
            $fileCounter2++
        } catch {
            Write-Host ">> Error processing shellcode match: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }
}

# Find thread parameters for shellcode
$fileCounter3 = 0
$tpMatches = [regex]::Matches($fileContent, 'threadParametersBase64\s*=\s*".+?"')
Write-Host ">> Found $($tpMatches.Count) thread parameter matches" -ForegroundColor Green

foreach ($match in $tpMatches) {
    if ($match.Value) {
        try {
            if ($match.Value.Length -lt 100) {
                continue
            }

            $blob = $match.Value -Replace 'threadParametersBase64 = "', '' -Replace '"$', ''
            $compressed = [System.Convert]::FromBase64String($blob)
            $decompressed = DecompressSC($compressed)

            $outputFile = Join-Path -Path $outputDirectory -ChildPath ("thread_parameters_{0}.bin" -f $fileCounter3)
            [System.IO.File]::WriteAllBytes($outputFile, $decompressed)

            Write-Host ">> Wrote decompressed thread parameters to: $outputFile" -ForegroundColor Green
            $fileCounter3++
        } catch {
            Write-Host ">> Error processing thread parameter match: $($_.Exception.Message)" -ForegroundColor Red
            continue 
        }
    }
} 

# Smaller base64 blocks, possibly commands run
$fileCounter4 = 0
$b64Matches = [regex]::Matches($fileContent, "(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)")
Write-Host ">> Found $($b64Matches.Count) base64 matches" -ForegroundColor Green

foreach ($match in $B64Matches) {
    if ($match.Value) {
        try {
            if ($match.Value.Length -lt 50 -or $match.Value.Length -gt 900) {
                continue
            }

            $decoded = [System.Convert]::FromBase64String($match.Value)
            $removedNullBytes = $decoded | Where-Object { $_ -ne 0 }
            $outputFile = Join-Path -Path $outputDirectory -ChildPath ("base64_{0}.txt" -f $fileCounter4)
            [System.IO.File]::WriteAllBytes($outputFile, $removedNullBytes)
            Write-Host ">> Wrote decoded base64 to: $outputFile" -ForegroundColor Green

            $fileCounter4++
        } catch {
            Write-Host ">> Error processing base64 match: $($_.Exception.Message)" -ForegroundColor Red
            continue 
        }
    }
}

Write-Host "Extraction complete. Files have been saved in $outputDirectory" -ForegroundColor Green
