<?php

    namespace cytodev\lib\cryptography\exceptions;

    use \Exception;
    use \Throwable;

    /**
     * Class CryptographyException
     *
     * @package io\cytodev\lib\cryptography\exceptions
     */
    class CryptographyException extends Exception {

        /**
         * CryptographyException constructor
         *
         * @param string         $message  The exception message
         * @param int            $code     The exception code
         * @param Throwable|null $previous The previous exception used for the
         *                                 exception chaining
         */
        public function __construct(string $message = "", int $code = 0, Throwable $previous = null) {
            parent::__construct($message, $code, $previous);
        }

        /**
         * Magic __toString
         *   Returns a very basic description for the raised exception
         *
         * @return string
         */
        public function __toString(): string {
            return sprintf("A %s was raised (%s)", get_class($this), $this->message);
        }

    }
