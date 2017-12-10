<?php

namespace Idoleg\JwtAuth\Test;

//https://github.com/tymondesigns/jwt-auth/blob/develop/tests/JWTGuardTest.php

use Idoleg\JwtAuth\Exceptions\JwtParseException;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Auth\EloquentUserProvider;
use Idoleg\JwtAuth\Jwt;
use Idoleg\JwtAuth\JwtGuard;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Mockery;

class JwtGuardTest extends AbstractTestCase
{

    /**
     * @var Jwt|\Mockery\MockInterface
     */
    protected $jwt;

    /**
     * @var JwtGuard|\Mockery\MockInterface
     */
    protected $guard;

    /**
     * @var \Illuminate\Contracts\Auth\UserProvider|\Mockery\MockInterface
     */
    protected $provider;

    /**
     * @var \Illuminate\Contracts\Auth\UserProvider|\Mockery\MockInterface
     */
    protected $request;

    protected $testConfig = [
        'jwt' => [
            'authToken' => [
                'verifyKey' => 'very_secret',
                'life' => 43200, // 12 часов: 60 секунд * 60 минут * 12 часов
            ],
            'refreshToken' => [
                'verifyKey' => 'very_secret',
                'life' => 2592000, // 1 месяц: 60 секунд * 60 минут * 24 часа * 30 дней
            ],
        ]
    ];

    public function setUp()
    {
        parent::setUp();

        $this->jwt = new JWT;
        $this->request = Request::create('/foo', 'GET');
        $this->provider = Mockery::mock(EloquentUserProvider::class);
        $this->guard = new JwtGuard($this->jwt, $this->request, $this->provider, $this->testConfig);
    }

    /**
     * @test
     */
    public function it_should_get_the_provider()
    {
        $this->assertInstanceOf(UserProvider::class, $this->guard->getProvider());
    }

    /**
     * @test
     */
    public function it_should_get_the_user()
    {
        //todo: исправить - в таком случае должно возврощать гостя
        $this->assertEquals(null, $this->guard->user());
    }

    /**
     * Тестирование аутентификации на основе объекта
     *
     * @test
     */
    public function it_should_login()
    {
        $user = Mockery::mock(User::class);
        $user->shouldReceive('getAttribute')
            ->with('name')
            ->andReturn('test');

        $this->guard->login($user);

        $this->assertEquals('test', $this->guard->user()->name);
    }

    /**
     * Тестирование аутентификации на основе учетных данных
     *
     * @test
     */
    public function it_should_login_by_credentials()
    {
        $user = Mockery::mock(User::class);
        $user->shouldReceive('getAttribute')->with('name')
            ->andReturn('test');

        $this->provider->shouldReceive('retrieveByCredentials')
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->andReturn(true);

        $this->assertTrue($this->guard->loginByCredentials(['name' => 'test', 'password' => 'pass']));
        $this->assertEquals('test', $this->guard->user()->name);
    }

    /**
     * Тестирование аутентификации на основе не правильных учетных данных
     *
     * @test
     */
    public function it_should_not_login_by_error_credentials()
    {
        $user = Mockery::mock(User::class);
        $user->shouldReceive('getAttribute')->with('name')
            ->andReturn('test');

        $this->provider->shouldReceive('retrieveByCredentials')
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->andReturn(false);

        $this->assertFalse($this->guard->loginByCredentials(['name' => 'test', 'password' => 'pass']));
        //todo: исправить - в таком случае должно возврощать гостя
        $this->assertEquals(null, $this->guard->user());
    }

    /**
     * Тестирование создания и проверки токена
     *
     * @test
     */
    public function create_and_parse_auth_token()
    {
        $signer = new Sha256();

        $user = Mockery::mock(User::class);
        $user->shouldReceive('getAttribute')->with('id')
            ->andReturn('1');

        $authToken = $this->guard->createAuthToken($user);
        $this->assertInstanceOf(Token::class, $this->guard->parseAuthToken($authToken));

        $this->assertException(\InvalidArgumentException::class, function () {
            $this->guard->parseAuthToken('error');
        });

        $errorToken = (string)$this->jwt->builder()
            ->setExpiration(time() - 1000)
            ->set('uid', $user->id)
            ->set('type', 'authToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseAuthToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('uid', $user->id)
            ->set('type', 'authToken')
            ->sign($signer, 'error_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseAuthToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('type', 'authToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseAuthToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('uid', $user->id)
            ->set('type', 'refreshAuthToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseAuthToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('uid', $user->id)
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseAuthToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('uid', $user->id)
            ->set('type', 'authToken')
            ->getToken();

        $this->assertException(\BadMethodCallException::class, function () use ($errorToken) {
            $this->guard->parseAuthToken($errorToken);
        });


    }


    /**
     * Тестирование аутентификации на основе токена
     *
     * @test
     */
    public function it_should_login_by_token()
    {
        $user = Mockery::mock(User::class);
        $user->shouldReceive('getAttribute')->with('id')
            ->andReturn(1);

        $this->provider->shouldReceive('retrieveById')
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->andReturn(false);

        $authToken = $this->guard->createAuthToken($user);

        $this->assertTrue($this->guard->loginByToken($authToken));
        $this->assertEquals(1, $this->guard->user()->id);

    }

    /**
     * Тестирование аутентификации на основе ложного токена
     *
     * @test
     */
    public function it_should_not_login_by_error_token()
    {
        $user = Mockery::mock(User::class);
        $user->shouldReceive('getAttribute')->with('id')
            ->andReturn(1);

        $this->provider->shouldReceive('retrieveById')
            ->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')
            ->andReturn(false);

        $errorToken = (string)$this->jwt->builder()
            ->set('uid', $user->id)
            ->set('type', 'authToken')
            ->sign(new Sha256(), 'error_secret')
            ->getToken();

        $this->assertFalse($this->guard->loginByToken($errorToken));
        //todo: исправить - в таком случае должно возврощать гостя
        $this->assertEquals(null, $this->guard->user());

    }

    /**
     * Тестирование создания и проверки токена
     *
     * @test
     */
    public function create_and_parse_refresh_token()
    {
        $signer = new Sha256();

        $user = Mockery::mock(User::class);
        $this->provider->shouldReceive('updateRememberToken')
            ->andReturn(true);
        $user->shouldReceive('getAttribute')->with('id')
            ->andReturn(1);
        $user->shouldReceive('getRememberToken')
            ->andReturn('test remember token');


        $authToken = $this->guard->createRefreshToken($user);
        $this->assertInstanceOf(Token::class, $this->guard->parseRefreshToken($authToken));

        $this->assertException(\InvalidArgumentException::class, function () {
            $this->guard->parseRefreshToken('error');
        });

        $errorToken = (string)$this->jwt->builder()
            ->setExpiration(time() - 1000)
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->sign($signer, 'error_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->set('type', 'refreshToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'ZrefreshToken')
            ->sign($signer, 'very_secret')
            ->getToken();

        $this->assertException(JwtParseException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->getToken();

        $this->assertException(\BadMethodCallException::class, function () use ($errorToken) {
            $this->guard->parseRefreshToken($errorToken);
        });

    }


    /**
     * Тестирование аутентификации на основе токена обновления
     *
     * @test
     */
    public function it_should_login_by_refresh_token()
    {
        $user = Mockery::mock(User::class);
        $this->provider->shouldReceive('updateRememberToken')
            ->andReturn(true);
        $this->provider->shouldReceive('retrieveByToken')
            ->andReturn($user);
        $user->shouldReceive('getAttribute')->with('id')
            ->andReturn(1);
        $user->shouldReceive('getRememberToken')
            ->andReturn('test remember token');
        $this->provider->shouldReceive('validateCredentials')
            ->andReturn(false);

        $authToken = $this->guard->createRefreshToken($user);

        $this->assertTrue($this->guard->loginByRefreshToken($authToken));
        $this->assertEquals(1, $this->guard->user()->id);

    }

    /**
     * Тестирование аутентификации на основе ложного токена обновления
     *
     * @test
     */
    public function it_should_not_login_by_refresh_error_token()
    {
        $user = Mockery::mock(User::class);
        $this->provider->shouldReceive('updateRememberToken')
            ->andReturn(true);
        $this->provider->shouldReceive('retrieveByToken')
            ->andReturn($user);
        $user->shouldReceive('getAttribute')->with('id')
            ->andReturn(1);
        $user->shouldReceive('getRememberToken')
            ->andReturn('test remember token');
        $this->provider->shouldReceive('validateCredentials')
            ->andReturn(false);

        $errorToken = (string)$this->jwt->builder()
            ->set('token', $user->getRememberToken())
            ->set('uid', $user->id)
            ->set('uip', $this->request->ip())
            ->set('type', 'refreshToken')
            ->sign(new Sha256(), 'error_secret')
            ->getToken();

        $this->assertFalse($this->guard->loginByRefreshToken($errorToken));
        //todo: исправить - в таком случае должно возврощать гостя
        $this->assertEquals(null, $this->guard->user());

    }


}
