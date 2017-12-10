<?php

namespace Idoleg\JwtAuth\Test;

use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase{

    /**
     * Asserts that the given callback throws the given exception.
     *
     * @param string $expectClass The name of the expected exception class
     * @param callable $callback A callback which should throw the exception
     */
    protected function assertException(string $expectClass, callable $callback)
    {
        try {
            $callback();
        } catch (\Throwable $exception) {
            $this->assertInstanceOf($expectClass, $exception);
            return;
        }

        $this->fail('No exception was thrown');
    }

}