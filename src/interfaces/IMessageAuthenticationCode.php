<?php

    namespace cytodev\lib\cryptography\interfaces;

    /**
     * Interface IMessageAuthenticationCode
     *
     * @package io\cytodev\lib\cryptography\interfaces
     */
    interface IMessageAuthenticationCode {

        /**
         * setMAC
         *   Sets the message authentication code used to encrypt the source
         *   message or decrypt the resulting encrypted message
         *
         * @param string $mac Message authentication code
         *
         * @return void
         */
        public function setMAC(string $mac): void;

        /**
         * setMAC
         *   gets the message authentication code used to encrypt the source
         *   message or decrypt the resulting encrypted message
         *
         * @return string
         */
        public function getMAC(): string;

    }
