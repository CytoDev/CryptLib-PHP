<?php

    namespace cytodev\lib\cryptography\interfaces;

    /**
     * <h1>Interface ICryptographicPassword</h1>
     *
     * @package cytodev\lib\cryptography\interfaces
     */
    interface ICryptographicPassword {

        /**
         * <h2>setPassword</h2>
         *   Sets a password to be used in an encrypted message
         *
         * @param string $password Password to use
         *
         * @return void
         */
        public function setPassword(string $password): void;

    }
