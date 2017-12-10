<?php

namespace Idoleg\JwtAuth;

use \Idoleg\JwtAuth\Contracts\Jwt as JwtContract;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;

class Jwt implements JwtContract
{
    public function builder()
    {
        return new Builder();
    }

    public function parser()
    {
        return new Parser();
    }

    public function validator()
    {
        return new ValidationData();
    }
}