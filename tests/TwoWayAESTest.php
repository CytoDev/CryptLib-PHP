<?php

    use io\cytodev\lib\cryptography\TwoWayAES;

    use io\cytodev\lib\cryptography\exceptions\CryptographyException;

    use PHPUnit\Framework\TestCase;
    use PHPUnit\Framework\ExpectationFailedException;

    use SebastianBergmann\RecursionContext\InvalidArgumentException;

    final class TwoWayAESTest extends TestCase {

        /**
         * testCanInstantiate
         *   Tests whether the class can actually be instantiated
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanInstantiate(): void {
            $this->assertInstanceOf(TwoWayAES::class, new TwoWayAES());
        }

        /**
         * testCanGetAvailableCiphers
         *   Tests whether the ciphers can be gathered from the meta:Cipher
         *
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanGetAvailableCiphers(): void {
            $this->assertInternalType("array", TwoWayAES::getAvailableCiphers());
            $this->assertInternalType("array", TwoWayAES::getAvailableAdvancedCiphers());
        }

        /**
         * testCanSetAndGetCipher
         *   Tests whether ciphers method can be changed
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanSetAndGetCipher(): void {
            $twoWayAES = new TwoWayAES();

            foreach(TwoWayAES::getAvailableCiphers() as $cipher) {
                $twoWayAES->setCipher($cipher);

                $this->assertEquals($cipher, $twoWayAES->getCipher());
            }
        }

        /**
         * testCanGetCipherInitialisationVectorLength
         *   Tests whether cipher initialisation vector lengths can be retrieved
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanGetCipherInitialisationVectorLength(): void {
            $twoWayAES = new TwoWayAES();

            foreach(TwoWayAES::getAvailableCiphers() as $cipher) {
                $twoWayAES->setCipher($cipher);

                $this->assertEquals(openssl_cipher_iv_length($cipher), $twoWayAES->getCipherIVLength());
            }
        }

        /**
         * testCanSetAndGetInitialisationVector
         *   Tests whether the initialisation vector can be set
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanSetAndGetInitialisationVector(): void {
            $twoWayAES = new TwoWayAES();

            foreach(TwoWayAES::getAvailableCiphers() as $cipher) {
                $twoWayAES->setCipher($cipher);

                $iv = openssl_random_pseudo_bytes($twoWayAES->getCipherIVLength());

                $twoWayAES->setIV($iv);

                $this->assertEquals($iv, $twoWayAES->getIV());
            }
        }

        /**
         * testCanEncrypt
         *   Tests whether the encryption works with nilled IV
         *
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         * @throws CryptographyException
         */
        public function testCanEncrypt(): void {
            $twoWayAES = new TwoWayAES("AES-128-CBC", hex2bin("8e7aaa24ad5128edda5181fc6f30e03f"));

            $tests = [
                "test"                                            => "953240e6b5ab7cf9ef11c5059e675729",
                "some words with spaces"                          => "b58dd4f5fe887417a0fced789807d4c3f1ff00a0f443855b4356bcb67dbf969c",
                "a-typical-string-with-words&special-characters;" => "10e084a7fe618463da0fcb519dd5e8386ca4a91a7073fb9ce9115ed4bf37a9f3d3a642b7844ad67b4f895d524e4de6a0",
                ":(){:|:;}:"                                      => "eaf1db6496f708c2aa408a65b8280788",
                "; DROP TABLE users"                              => "742f548369f1a94fb800986080eafe2c886daf6e45e68edf36ed0921667199dc",
                "null"                                            => "9a78c48ea775df205322731cd6a2c33d"
            ];

            foreach($tests as $test => $expected)
                $this->assertEquals($expected, bin2hex($twoWayAES->encrypt($test)));
        }

        /**
         * testCanDecrypt
         *   Tests whether the decryption works with nilled IV
         *
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         * @throws CryptographyException
         */
        public function testCanDecrypt(): void {
            $twoWayAES = new TwoWayAES("AES-128-CBC", hex2bin("8e7aaa24ad5128edda5181fc6f30e03f"));

            $tests = [
                "953240e6b5ab7cf9ef11c5059e675729"                                                                 => "test",
                "b58dd4f5fe887417a0fced789807d4c3f1ff00a0f443855b4356bcb67dbf969c"                                 => "some words with spaces",
                "10e084a7fe618463da0fcb519dd5e8386ca4a91a7073fb9ce9115ed4bf37a9f3d3a642b7844ad67b4f895d524e4de6a0" => "a-typical-string-with-words&special-characters;",
                "eaf1db6496f708c2aa408a65b8280788"                                                                 => ":(){:|:;}:",
                "742f548369f1a94fb800986080eafe2c886daf6e45e68edf36ed0921667199dc"                                 => "; DROP TABLE users",
                "9a78c48ea775df205322731cd6a2c33d"                                                                 => "null"
            ];

            foreach($tests as $test => $expected)
                $this->assertEquals($expected, $twoWayAES->decrypt(hex2bin($test)));
        }

        /**
         * testCanFunctionallyUsePassword
         *   Tests whether the password can be set and is useful in the
         *   encryption process
         *
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         * @throws CryptographyException
         */
        public function testCanFunctionallyUsePassword(): void {
            $twoWayAES = new TwoWayAES("AES-128-CBC", hex2bin("8e7aaa24ad5128edda5181fc6f30e03f"));

            $tests = [
                "test" => [
                    "trustno1"     => "d88acd297929e28a54b5f4da20ccf08a",
                    "password"     => "3376294971dd89914b64646a0ad16c77",
                    ":(){:|:;}:"   => "9e37096142eaa84f0f581b3d51949dc4",
                    "qwertyazerty" => "a7ad1c9139ec5fe45f87cb74f9949611"
                ],
                "some words with spaces" => [
                    "trustno1"     => "439634a32444c7a9f9eb793b5974670e49569b1ff26403d9b327b19e15b3746c",
                    "password"     => "416e4450a9dc6f547ce3a97a50f7ef070f8a364c3240c61903c724f6be7d83f6",
                    ":(){:|:;}:"   => "01195b1651cb25d2b83ffbb933c9c47d871a718c41539aee3cc96087f314c8f2",
                    "qwertyazerty" => "d8af421d3ec4c3dc8c3278d0438d9e8f4d8e29d6690099a75aff953122dcbd23"
                ],
                "a-typical-string-with-words&special-characters;" => [
                    "trustno1"     => "8a135d77ac8bf82bb3642376bc53ae9e80bc9a8bdaeff436ee19fc0b9e7d0cc55d46feb201dd8d78814f8600f87c9dce",
                    "password"     => "b03a33d999cb116f90882416fa7d333503de12e18d1372b7200663796c73f4c5db873c7bf985b29ea1be5418d758ca40",
                    ":(){:|:;}:"   => "cd25cee43cc107bcd9dafd9dab6d9d78a95c2489f772fce8e9b9a9a0d0a52731e1dcd89f39b55d45aef4499bb00763ba",
                    "qwertyazerty" => "fed1e1b977901ce670fbc11dcccf2fa1fa9c7f304a0ff0c627819118beea51d615c453f220f73c1cd6812f99356e6c8a"
                ],
                ":(){:|:;}:" => [
                    "trustno1"     => "e5f0ff32f59bf0f1315ed80911de16ec",
                    "password"     => "cb6bff7eee39295d7e8fb79d765038bc",
                    ":(){:|:;}:"   => "9e1f1c0b362597ac569145872836b427",
                    "qwertyazerty" => "42bf3e9e0cb23dc8edeb6ac3d0bb62c9"
                ],
                "; DROP TABLE users" => [
                    "trustno1"     => "04adac1de33cd3a91176e8442a5a34b86594fd8e3ab8c61cd6b90ac828ef3b2a",
                    "password"     => "e224b0c7184960422523c3368ccc0bd2b9c3ac9fb21a85c4b5b89000b3080aaa",
                    ":(){:|:;}:"   => "737e8215c4f2c79988a4971cfd862fa97f6d68d00bb8d6e0cfa854ced3adb4fa",
                    "qwertyazerty" => "20651aa3cb14bd5477050f2253bf4363a18f1ebd93309e1eb665781f023f3305"
                ],
                "null" => [
                    "trustno1"     => "288fbf407359e7fa203c17e0eb7097b7",
                    "password"     => "96bd35fa337277e50e75f609ca4388b4",
                    ":(){:|:;}:"   => "f4aa71b9d94c5c004665998e46a45a83",
                    "qwertyazerty" => "30752204b6743defbe65a0df76c5e84f"
                ]
            ];

            foreach($tests as $phrase => $test) {
                foreach($test as $password => $encrypted) {
                    $twoWayAES->setPassword($password);

                    $this->assertEquals($encrypted, bin2hex($twoWayAES->encrypt($phrase)));
                    $this->assertEquals($phrase, $twoWayAES->decrypt(hex2bin($encrypted)));
                }

                $twoWayAES->setPassword("");

                foreach($test as $password => $encrypted) {
                    $this->assertNotEquals($encrypted, bin2hex($twoWayAES->encrypt($phrase)));
                    $this->assertNotEquals($phrase, $twoWayAES->decrypt(hex2bin($encrypted)));
                }
            }
        }

        /**
         * testIsAdvanced
         *   Tests whether advanced options can be used
         *
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testIsAdvanced(): void {
            $this->assertNotEmpty(TwoWayAES::getAvailableAdvancedCiphers());
        }

        /**
         * testCanFunctionallyUseTag
         *   Tests whether the tag can be used and is useful in the encryption
         *   process
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanFunctionallyUseTag(): void {
            $twoWayAES = new TwoWayAES();

            $tests = [
                "test",
                "some words with spaces",
                "a-typical-string-with-words&special-characters;",
                ":(){:|:;}:",
                "; DROP TABLE users",
                "null"
            ];

            foreach($tests as $test) {
                $tag  = null;
                $data = null;

                $data = $twoWayAES->encrypt($test, $tag);

                $this->assertNotNull($tag);
                $this->assertNotNull($data);

                $this->assertEquals($test, $twoWayAES->decrypt($data, $tag));
                $this->assertNotEquals($test, $twoWayAES->decrypt($data, "\0\0\0\0"));
            }
        }

        /**
         * testCanFunctionallyUseMessageAuthenticationCode
         *   Tests whether the message authentication code can be used and is
         *   useful in the encryption process
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanFunctionallyUseMessageAuthenticationCode(): void {
            $twoWayAES = new TwoWayAES();

            $tests = [
                "test" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "some words with spaces" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "a-typical-string-with-words&special-characters;" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                ":(){:|:;}:" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "; DROP TABLE users" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "null" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ]
            ];

            foreach($tests as $test => $keys) {
                foreach($keys as $key) {
                    $tag  = null;
                    $data = null;

                    $twoWayAES->setMAC($key);

                    $this->assertEquals($key, $twoWayAES->getMAC());

                    $data = $twoWayAES->encrypt($test, $tag);

                    $this->assertNotNull($tag);
                    $this->assertNotNull($data);

                    $this->assertEquals($test, $twoWayAES->decrypt($data, $tag));
                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, "\0\0\0\0"));

                    $twoWayAES->setMAC("");

                    $this->assertEquals("", $twoWayAES->getMAC());
                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, $tag));
                }
            }
        }

        /**
         * testCanFunctionallyUsePasswordAndTag
         *   Tests whether the password can be used in combination with the tag
         *   and is useful in the encryption process
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanFunctionallyUsePasswordAndTag(): void {
            $twoWayAES = new TwoWayAES();

            $tests = [
                "test" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "some words with spaces" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "a-typical-string-with-words&special-characters;" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                ":(){:|:;}:" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "; DROP TABLE users" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ],
                "null" => [
                    "trustno1",
                    "password",
                    ":(){:|:;}:",
                    "qwertyazerty"
                ]
            ];

            foreach($tests as $test => $keys) {
                foreach($keys as $key) {
                    $tag  = null;
                    $data = null;

                    $twoWayAES->setPassword($key);

                    $data = $twoWayAES->encrypt($test, $tag);

                    $this->assertNotNull($tag);
                    $this->assertNotNull($data);

                    $this->assertEquals($test, $twoWayAES->decrypt($data, $tag));
                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, "\0\0\0\0"));

                    $twoWayAES->setPassword("");

                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, $tag));
                }
            }
        }

        /**
         * testCanFunctionallyUsePasswordAndMessageAuthenticationCode
         *   Tests whether the password can be used in combination with the
         *   message authentication code and is useful in the encryption process
         *
         * @throws CryptographyException
         * @throws ExpectationFailedException
         * @throws InvalidArgumentException
         */
        public function testCanFunctionallyUsePasswordAndMessageAuthenticationCode(): void {
            $twoWayAES = new TwoWayAES();

            $tests = [
                "test" => [
                    "trustno1"     => "Bit",
                    "password"     => "Byte",
                    ":(){:|:;}:"   => "Picture of a tree",
                    "qwertyazerty" => "Test case"
                ],
                "some words with spaces" => [
                    "trustno1"     => "Bit",
                    "password"     => "Byte",
                    ":(){:|:;}:"   => "Picture of a tree",
                    "qwertyazerty" => "Test case"
                ],
                "a-typical-string-with-words&special-characters;" => [
                    "trustno1"     => "Bit",
                    "password"     => "Byte",
                    ":(){:|:;}:"   => "Picture of a tree",
                    "qwertyazerty" => "Test case"
                ],
                ":(){:|:;}:" => [
                    "trustno1"     => "Bit",
                    "password"     => "Byte",
                    ":(){:|:;}:"   => "Picture of a tree",
                    "qwertyazerty" => "Test case"
                ],
                "; DROP TABLE users" => [
                    "trustno1"     => "Bit",
                    "password"     => "Byte",
                    ":(){:|:;}:"   => "Picture of a tree",
                    "qwertyazerty" => "Test case"
                ],
                "null" => [
                    "trustno1"     => "Bit",
                    "password"     => "Byte",
                    ":(){:|:;}:"   => "Picture of a tree",
                    "qwertyazerty" => "Test case"
                ]
            ];

            foreach($tests as $test => $keys) {
                foreach($keys as $key => $password) {
                    $tag  = null;
                    $data = null;

                    $twoWayAES->setPassword($password);
                    $twoWayAES->setMAC($key);

                    $this->assertEquals($key, $twoWayAES->getMAC());

                    $data = $twoWayAES->encrypt($test, $tag);

                    $this->assertNotNull($tag);
                    $this->assertNotNull($data);

                    $this->assertEquals($test, $twoWayAES->decrypt($data, $tag));
                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, "\0\0\0\0"));

                    $twoWayAES->setMAC("");

                    $this->assertEquals("", $twoWayAES->getMAC());
                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, $tag));

                    $twoWayAES->setMAC($key);

                    $this->assertEquals($key, $twoWayAES->getMAC());
                    $this->assertEquals($test, $twoWayAES->decrypt($data, $tag));

                    $twoWayAES->setPassword("");

                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, $tag));

                    $twoWayAES->setMAC("");

                    $this->assertEquals("", $twoWayAES->getMAC());
                    $this->assertNotEquals($test, $twoWayAES->decrypt($data, $tag));
                }
            }
        }

    }
