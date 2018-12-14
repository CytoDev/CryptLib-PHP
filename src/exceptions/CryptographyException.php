<?php

    namespace cytodev\lib\cryptography\exceptions;

    use \Exception;
    use \Throwable;

    /**
     * <h1>Class CryptographyException</h1>
     *
     * @package cytodev\lib\cryptography\exceptions
     */
    class CryptographyException extends Exception {

        /**
         * <h2>CryptographyException constructor.</h2>
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
         * <h2>Magic __toString</h2>
         *   Returns a very basic description for the raised exception
         *
         * @return string
         */
        public function __toString(): string {
            return sprintf("A %s was raised (%s)", get_class($this), $this->message);
        }

    }
