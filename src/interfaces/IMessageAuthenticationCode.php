<?php

    namespace cytodev\lib\cryptography\interfaces;

    /**
     * <h1>Interface IMessageAuthenticationCode</h1>
     *
     * @package cytodev\lib\cryptography\interfaces
     */
    interface IMessageAuthenticationCode {

        /**
         * <h2>setMAC</h2>
         *   Sets the message authentication code used to encrypt the source
         *   message or decrypt the resulting encrypted message
         *
         * @param string $mac Message authentication code
         *
         * @return void
         */
        public function setMAC(string $mac): void;

        /**
         * <h2>setMAC</h2>
         *   gets the message authentication code used to encrypt the source
         *   message or decrypt the resulting encrypted message
         *
         * @return string
         */
        public function getMAC(): string;

    }
