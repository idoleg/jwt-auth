<?php

namespace Idoleg\JwtAuth;

use Idoleg\JwtAuth\Exceptions\JwtParseException;
use Idoleg\JwtAuth\Contracts\Jwt;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as Auth;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;


class JwtGuard implements Guard
{
    use GuardHelpers;

    /**
     * The JWT instance.
     *
     * @var Jwt
     */
    protected $jwt;

    /**
     * The UserProvider instance.
     *
     * @var Auth
     */
    protected $auth;

    /**
     * The Request instance.
     *
     * @var Auth
     */
    protected $request;

    /**
     * Auth config array
     *
     * @var array
     */
    protected $config;

    /**
     * Default auth configuration
     *
     * @var array
     */
    protected $defaultConfig = [
        'authToken' => [
            'verifyKey' => 'secret',
            'life' => 43200, // 12 часов: 60 секунд * 60 минут * 12 часовx
        ],
        'refreshToken' => [
            'verifyKey' => 'secret',
            'life' => 2592000, // 1 месяц: 60 секунд * 60 минут * 24 часа * 30 дней
        ],
    ];

    /**
     * JwtGuard constructor.
     *
     * @param Jwt $jwt
     * @param UserProvider $provider
     * @param Request $request
     * @param $config
     */
    public function __construct(Jwt $jwt, Request $request, UserProvider $provider, $config)
    {
        $this->defaultConfig['authToken']['verifyKey'] = env('JWT_AUTH_KEY');
        $this->defaultConfig['refreshToken']['verifyKey'] = env('JWT_REFRESH_KEY');

        $this->jwt = $jwt;
        $this->provider = $provider;
        $this->request = $request;
        $this->config = ($config['config'] ?? []) + $this->defaultConfig;
    }

    /**
     * Аутентифицировать пользователя в системе с помощью модели пользователя
     *
     * @param Authenticatable $user
     * @return bool
     */
    public function login(Authenticatable $user)
    {
        $this->setUser($user);

        return true;
    }

    /**
     * Аутентифицировать пользователя в системе с помощью масива учетных данных (name/email, password)
     * В случае успеха возвращает TRUE, иначе FALSE
     *
     * @param array $credentials
     * @return bool
     */
    public function loginByCredentials(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->provider->validateCredentials($user, $credentials)) {

            return $this->login($user);
        }

        return false;
    }

    /**
     * Аутентифицировать пользователя в системе с помощью jwt токена авторизации (authToken)
     * В случае успеха возвращает TRUE, иначе FALSE
     *
     * @param $token
     * @return bool
     */
    public function loginByToken($token)
    {
        try {
            $token = $this->parseAuthToken($token);
        } catch (JwtParseException $e) {
            return false;
        } catch (\InvalidArgumentException $e) {
            return false;
        } catch (\BadMethodCallException $e) {
            return false;
        }

        $user = $this->provider->retrieveById($token->getClaim('uid'));

        if (!is_null($user)) {
            return $this->login($user);
        }

        return false;

    }

    /**
     * Аутентифицировать пользователя в системе с помощью jwt токена обновления (refreshToken)
     *
     * @param $token
     * @return bool
     */
    public function loginByRefreshToken($token)
    {
        try {
            $token = $this->parseRefreshToken($token);
        } catch (JwtParseException $e) {
            return false;
        } catch (\InvalidArgumentException $e) {
            return false;
        } catch (\BadMethodCallException $e) {
            return false;
        }

        $user = $this->provider->retrieveByToken($token->getClaim('uid'), $token->getClaim('token'), $token->getClaim('uip'));

        if (!is_null($user)) {
            return $this->login($user);
        }

        return false;
    }

    /**
     * Аутентифицировать пользователя в системе с помощью заголока Authorization: Bearer <authToken>
     *
     * @param Request $request
     * @return bool
     * @throws JwtParseException
     */
    public function loginByRequest(Request $request = NULL)
    {
        $request = $request ?? $this->request;

        try {
            $token = $this->parseTokenFromRequest($request);
        } catch (JwtParseException $e) {
            return false;
        } catch (\InvalidArgumentException $e) {
            return false;
        } catch (\BadMethodCallException $e) {
            return false;
        }

        $user = $this->provider->retrieveById($token->getClaim('uid'));

        if (!is_null($user)) {
            return $this->login($user);
        }
    }

    /**
     * Проверить вхождение заголовка с токеном в запрос
     *
     * @param Request $request
     * @return bool
     */
    public function isIncludedTokenInRequest(Request $request = NULL)
    {
        $request = $request ?? $this->request;

        return $request->bearerToken() ? true : false;
    }

    /**
     * Проверить вхождение заголовка с токеном в запрос и выбросить ошибку в случае его отсутсвия
     *
     * @param Request $request
     */
    public function requireTokenInRequest(Request $request = NULL)
    {
        if (!$this->isIncludedTokenInRequest($request)) {
            throw new BadRequestHttpException('Token could not be parsed from the request.', NULL, 401);
        }
    }

    /**
     * Пропарсить токен из запроса
     *
     * @param Request|NULL $request
     * @return bool
     * @throws JwtParseException
     */
    public function parseTokenFromRequest(Request $request = NULL)
    {
        $request = $request ?? $this->request;

        if ($request->bearerToken()) {
            return $this->parseAuthToken($request->bearerToken());
        }

        return false;
    }

    /**
     * Получить токен из запроса
     *
     * @param Request|NULL $request
     * @return null|string
     */
    public function getTokenFromRequest(Request $request = NULL)
    {
        $request = $request ?? $this->request;

        return $request->bearerToken();
    }

    /**
     * Создать токен
     *
     * @param Authenticatable|NULL $user
     * @param bool $returnObject
     * @return mixed
     */
    public function createAuthToken(Authenticatable $user = NULL, $returnObject = false)
    {
        $user = $user ?? $this->user;
        if (is_null($user)) throw new \InvalidArgumentException('User не указан');

        $signer = new Sha256();

        $token = $this->jwt->builder()
            ->setExpiration(time() + $this->config['authToken']['life'])
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'authToken')
            ->sign($signer, $this->config['authToken']['verifyKey'])
            ->getToken();

        if ($returnObject) {
            return $token;
        }

        return (string)$token;

    }

    /**
     * Пропарсить токен
     *
     * @param string $token
     * @return mixed
     * @throws JwtParseException
     */
    public function parseAuthToken($token)
    {
        $token = $this->jwt->parser()
            ->parse($token);

        $signer = new Sha256();

        if (
            $token->validate($this->jwt->validator())
            and $token->verify($signer, $this->config['authToken']['verifyKey'])
            and $token->hasClaim('uid')
            and $token->hasClaim('uip')
            and $token->hasClaim('type')
            and $token->getClaim('type') == 'authToken'
        ) {
            return $token;
        }

        throw new JwtParseException('Auth JWT не валидный');

    }

    /**
     * Создать токен обновления
     *
     * @param Authenticatable|NULL $user
     * @param bool $returnObject
     * @return mixed
     */
    public function createRefreshToken(Authenticatable $user = NULL, $returnObject = false)
    {
        $user = $user ?? $this->user;
        if (is_null($user)) throw new \InvalidArgumentException('User не указан');;

        $rememberToken = Str::random(64);
        $this->provider->updateRememberToken($user, $rememberToken, $this->request->ip());

        $signer = new Sha256();

        $token = $this->jwt->builder()
            ->setExpiration(time() + $this->config['refreshToken']['life'])
            ->set('token',$rememberToken)
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->sign($signer, $this->config['refreshToken']['verifyKey'])
            ->getToken();

        if ($returnObject) {
            return $token;
        }

        return (string)$token;
    }

    /**
     * Пропарсить токен обновления
     *
     * @param $token
     * @return mixed
     * @throws JwtParseException
     */
    public function parseRefreshToken($token)
    {
        $token = $this->jwt->parser()
            ->parse($token);

        $signer = new Sha256();

        if (
            $token->validate($this->jwt->validator())
            and $token->verify($signer, $this->config['authToken']['verifyKey'])
            and $token->hasClaim('token')
            and $token->hasClaim('type')
            and $token->hasClaim('uid')
            and $token->hasClaim('uip')
            and $token->getClaim('type') == 'refreshToken'
            and $token->getClaim('uip') == $this->request->ip()
        ) {
            return $token;
        }

        throw new JwtParseException('Refresh JWT не валидный');
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        return $this->user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return $this->loginByCredentials($credentials);
    }
}