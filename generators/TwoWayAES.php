<?php

    require_once("../vendor/autoload.php");

    use cytodev\lib\cryptography\TwoWayAES;

    $directory = "output/" . substr(basename(__FILE__), 0, -4);

    if(!file_exists($directory)) {
        if(!mkdir($directory)) {
            printf("Unable to create %s directory\n", $directory);

            exit(1);
        }
    }

    /**
     * writeFile
     *   Write data to a file
     *
     * @param  string $filePath File path to write $data to
     * @param  mixed  $data     Data to write to $filePath
     *
     * @return boolean
     */
    function writeFile(string $filePath, $data) {
        $handle = fopen($filePath, "w");

        if($handle === false)
            return false;

        if(fwrite($handle, $data) === false) {
            fclose($handle);

            return false;
        }

        fclose($handle);

        return true;
    }

    $index = 0;

    $options = getopt("h", [
        "help",
        "password:",
        "mac:"
    ], $index);

    if(isset($options["help"]) || isset($options["h"]) || (empty($options) && !isset($argv[$index]))) {
        echo <<<EOF
SYNOPSIS
    2waesenc [options] input

SYNOPSIS
    -h, --help
        Display this help message
    --password
        Set a password to use during encryption
    --mac
        Set a message authentication code to use during encryption

EXAMPLES
    Without options
        php 2waesenc "input string"
    With password
        php 2waesenc --password="password" "input string"
    With MAC
        php 2waesenc --mac="message authentication code" "input string"
    With password and MAC
        php 2waesenc --password="password" --mac="message authentication code" "input string"

TRICKS
    If you  really like to  confuse the **** out of people who  can potentially
    get a hold of  your  .mac  file  (which  should  be an  impressive  feat in
    itself), you can  try  any of the following  commands and use them as input
    for the "--mac" option:

    Get the wikipedia page for ethical hacking, dump the hex data, and base64
    encode it
        wget -O - -o /dev/null 'https://en.wikipedia.org/wiki/White_hat_(computer_security)' | hexdump | base64

    Get a random picture from picsum.photos, base64 encode it, and dump the hex
        wget -O - -o /dev/null 'https://picsum.photos/64?random' | base64 | hexdump

    [UNIX ONLY] Get 1024 lines of random data from /dev/urandom and base64
                encode it
                    od -h /dev/urandom | head -n 1024 | base64

    [UNIX only] get 1024 characters worth of random data from /dev/urandom and
                base64 encode it
                    cat /dev/urandom | head -c 1024 | base64

EOF;
        exit(0);
    }

    if(!isset($argv[$index])) {
        printf("No input received\n");

        exit(1);
    }

    $twoWayAES = new TwoWayAES("aes-128-ccm");

    $iv  = $twoWayAES->getIV();
    $tag = null;

    $output = [
        ".iv"  => writeFile("{$directory}/.iv", $iv)
    ];

    if(isset($options["password"]))
        $twoWayAES->setPassword($options["password"]);

    if(isset($options["mac"])) {
        $output[".mac"] = writeFile("{$directory}/.mac", $options["mac"]);

        $twoWayAES->setMAC($options["mac"]);
    }

    $result = $twoWayAES->encrypt($argv[$index], $tag);

    $output["#"] = writeFile("{$directory}/#", $tag);

    printf("Input..........: %s\n", $argv[$index]);
    printf("Using password.: %s\n", isset($options["password"])  ? "yes" : "no");
    printf("Using mac......: %s\n", isset($options["mac"])       ? "yes" : "no");
    printf("Output.........: %s\n\n", bin2hex($result));

    foreach ($output as $file => $written)
        printf("%s \"%s\" to %s\n", $written ? "Wrote" : "Unable to write", $file, realpath($directory));

    exit(0);
