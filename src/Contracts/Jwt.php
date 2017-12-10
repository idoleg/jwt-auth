<?php

namespace Idoleg\JwtAuth\Contracts;


interface Jwt
{

    public function builder();

    public function parser();

    public function validator();

}