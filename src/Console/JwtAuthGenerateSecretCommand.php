<?php

namespace Idoleg\JwtAuth\Console;

use Illuminate\Support\Str;
use Illuminate\Console\Command;

class JWTAuthKeyGenerateSecretCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'jwt-auth:secret 
        {--a|auth : Сгенерировать только ключ для токенов авторизации}
        {--r|refresh : Сгенерировать только ключ для токенов обновления токена авторизации}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Установить ключи для верефикации токенов авторизации';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {

        $keyRefresh = Str::random(32);

        if (file_exists($path = $this->envPath()) === false) {
            $this->comment('Отсутсвует файл среды .env');
            return;
        }
        if ($this->isConfirmed() === false) {
            $this->comment('Phew... No changes were made to your secret key.');
            return;
        }

        if ($this->option('auth')) {
            $this->generateAuthKey();
            return;
        } elseif ($this->option('refresh')) {
            $this->generateRefreshKey();
            return;
        } else {
            $this->generateAuthKey();
            $this->generateRefreshKey();
            return;
        }

    }

    protected function generateAuthKey()
    {
        $path = $this->envPath();
        $authKey = Str::random(32);

        if (Str::contains(file_get_contents($path), 'JWT_AUTH_KEY') === false) {
            // update existing entry
            file_put_contents($path, PHP_EOL . "JWT_AUTH_KEY=$authKey", FILE_APPEND);
        } else {
            // create new entry
            file_put_contents($path, str_replace(
                'JWT_AUTH_KEY=' . env('JWT_AUTH_KEY'),
                'JWT_AUTH_KEY=' . $authKey, file_get_contents($path)
            ));
        }
        $this->info("jwt-auth JWT_AUTH_KEY = [$authKey] set successfully.");
    }

    protected function generateRefreshKey()
    {
        $path = $this->envPath();
        $refreshKey = Str::random(32);

        if (Str::contains(file_get_contents($path), 'JWT_REFRESH_KEY') === false) {
            // update existing entry
            file_put_contents($path, PHP_EOL . "JWT_REFRESH_KEY=$refreshKey", FILE_APPEND);
        } else {
            // create new entry
            file_put_contents($path, str_replace(
                'JWT_REFRESH_KEY=' . env('JWT_REFRESH_KEY'),
                'JWT_REFRESH_KEY=' . $refreshKey, file_get_contents($path)
            ));
        }
        $this->info("jwt-auth JWT_REFRESH_KEY = [$refreshKey] set successfully.");
    }

    /**
     * Display the key.
     *
     * @param  string $key
     *
     * @return void
     */
    protected function displayKey($key)
    {
        $this->laravel['config']['jwt.secret'] = $key;
        $this->info("jwt-auth secret [$key] set successfully.");
    }

    /**
     * Check if the modification is confirmed.
     *
     * @return bool
     */
    protected function isConfirmed()
    {
        return $this->confirm(
            'Это приведет к утрате всех выданных токенов. Продолжить?'
        );
    }

    /**
     * Get the .env file path.
     *
     * @return string
     */
    protected function envPath()
    {
        if (method_exists($this->laravel, 'environmentFilePath')) {
            return $this->laravel->environmentFilePath();
        }
        return $this->laravel->basePath('.env');
    }
}
