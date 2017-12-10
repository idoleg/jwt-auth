<?php

namespace Idoleg\JwtAuth\Providers;

use Auth;
use Idoleg\JwtAuth\Console\JWTAuthKeyGenerateSecretCommand;
use Idoleg\JwtAuth\Contracts\Jwt;
use Idoleg\JwtAuth\JwtGuard;
use Illuminate\Support\ServiceProvider;

class JwtServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton(Jwt::class, function ($app) {

            return new \Idoleg\JwtAuth\Jwt();

        });

    }

    public function boot()
    {

        if ($this->app->runningInConsole()) {
            $this->commands([
                JWTAuthKeyGenerateSecretCommand::class
            ]);
        }

        Auth::extend('jwt', function ($app, $name, array $config) {

            return $app->make(JwtGuard::class, ['config' => $config]);

        });
    }
}