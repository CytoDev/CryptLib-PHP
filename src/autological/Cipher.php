<?php

    namespace cytodev\lib\cryptography\autological;

    use cytodev\lib\cryptography\exceptions\CryptographyException;

    /**
     * Class Cipher
     *
     * @package io\cytodev\lib\cryptography\autological
     */
    abstract class Cipher {

        /**
         * $cipher
         *
         * @var string
         */
        protected $cipher = null;

        /**
         * $advanced
         *
         * @var bool
         */
        protected $advanced = false;

        /**
         * $iv
         *
         * @var string
         */
        protected $iv = null;

        /**
         * Cipher constructor.
         *
         * @param string $cipher Cipher method [defaults: null]
         * @param string $iv     Initialization vector [defaults: null]
         *
         * @throws CryptographyException When no ciphers are available
         * @throws CryptographyException When $cipher is not available
         * @throws CryptographyException When $iv is not the correct length for
         *                               the current cipher
         */
        public function __construct(string $cipher = null, string $iv = null) {
            if($cipher === null) {
                $advancedCiphers = self::getAvailableAdvancedCiphers();
                $ciphers         = self::getAvailableCiphers();

                if(!empty($advancedCiphers)) {
                    $cipher = $advancedCiphers[0];
                } elseif(!empty($ciphers)) {
                    $cipher = $ciphers[0];
                } else {
                    throw new CryptographyException("No ciphers available");
                }
            }

            $this->setCipher($cipher);

            if($iv === null)
                $iv = openssl_random_pseudo_bytes($this->getCipherIVLength());

            $this->setIV($iv);
        }

        /**
         * getAvailableCiphers
         *   Gets all available cipher methods
         *
         * @return array
         */
        public static function getAvailableCiphers(): array {
            return openssl_get_cipher_methods();
        }

        /**
         * getAvailableAdvancedCiphers
         *   Gets all available advanced cipher methods
         *
         * @return array
         */
        public static function getAvailableAdvancedCiphers(): array {
            $advancedCiphers = [];

            foreach(self::getAvailableCiphers() as $cipher) {
                if(stripos($cipher, "CCM") !== false || stripos($cipher, "CGM") !== false)
                    array_push($advancedCiphers, $cipher);
            }

            return $advancedCiphers;
        }

        /**
         * setCipher
         *   Sets the cipher method and destroys the $iv value
         *
         * @param string $cipher The cipher method
         *
         * @throws CryptographyException When $cipher is not available
         */
        public function setCipher(string $cipher): void {
            if(!in_array($cipher, $this->getAvailableCiphers()))
                throw new CryptographyException(sprintf("Cipher \"%s\" is not available", $cipher));

            $this->advanced = in_array($cipher, $this->getAvailableAdvancedCiphers());
            $this->cipher   = $cipher;
            $this->iv       = null;
        }

        /**
         * getCipher
         *   Gets the cipher method
         *
         * @return string
         */
        public function getCipher(): string {
            return $this->cipher;
        }

        /**
         * getCipherIVLength
         *   Gets the initialization vector length for the current cipher
         *
         * @return int
         */
        public function getCipherIVLength(): int {
            if($this->cipher === null)
                return 0;

            return openssl_cipher_iv_length($this->cipher);
        }

        /**
         * setIV
         *   Sets the initialization vector
         *
         * @param string $iv Initialization vector
         *
         * @throws CryptographyException When $iv is not the correct length for
         *                               the current cipher
         */
        public function setIV(string $iv): void {
            if(strlen($iv) !== $this->getCipherIVLength())
                throw new CryptographyException(sprintf("Invalid IV length (%d) for cipher \"%s\" (requires %d)", strlen($iv), $this->cipher, $this->getCipherIVLength()));

            $this->iv = $iv;
        }

        /**
         * getIV
         *   Gets the initialization vector
         *
         * @return string Initialization vector
         */
        public function getIV(): string {
            return $this->iv;
        }

    }
