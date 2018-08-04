<?php

    namespace io\cytodev\lib\cryptography\interfaces;

    /**
     * Interface ICryptographicPassword
     *
     * @package io\cytodev\lib\cryptography\interfaces
     */
    interface ICryptographicPassword {

        /**
         * setPassword
         *   Sets a password to be used in an encrypted message
         *
         * @param string $password Password to use
         *
         * @return void
         */
        public function setPassword(string $password): void;

    }
