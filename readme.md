## JWT guard

#### Конфигурация

**config/auth.php**

```php
['guards' => [
        'api' => [  // название вашего защитника, можете указать любое, главное что бы оно же было в секции "defaults"
            'driver' => 'jwt', // обязательно укажите название драйвера "jwt"
            'provider' => 'users', // провайдер, название секции из "providers"
            'config' => [
                'authToken' => [
                    'verifyKey' => env('JWT_AUTH_KEY'), // ключ, которым будут подписыватся токены авторизации
                    'life' => 2592000, // время жизни токенов авторизации
                ],
                'guest' => [ // в этой секции возможно указать Eloquent Model и ее ID, она будет возвращаться, когда никакой пользователь не авторизован в системе. Если здесь указано false, будет возвращаться null (как стандартно в Laravel)
                    'id' => 1,
                    'model' => App\Models\User::class,
                ],
            ]
        ],
    ]
]
```
#### Методы

 1. **login($user)** - авторизровать пользователя по его Eloquent Model
 2. **loginByCredentials($credentials)** - аутентифицировать пользователя на основе его учетных данных 
 3. **loginByToken($token)** - авторизовать пользователя на основе auth token
 4. **loginByRequest($request = null)** - авторизовать пользователя на основе заголовка Authorization в запросе. Если не передан аргумент $request, проверка идет для текущего запроса

 5. **createAuthToken($user = null)** - выписать токен авторизации для пользователя. Если не указан $user, токен выписывается для авторизованногов системе пользователя

#### Guest

Если в конфигурации указана секция "guest", то в случае, если ни один пользователь не авторизован в системе, будет возвращаться не null при попытке его получить, а указанная в этой секции Eloquent Model.

## EloquentTokenUser Provider

2 таблицы (модели)
 1. user - для хранения пользователей
 2. user_tokens - для хранения токенов, по которым пользователи могут аутентифироваться в длительной перспективе

 #### Поля в таблице user_tokens
 
```php
    $table->increments('id');

    $table->unsignedInteger('user_id');

    $table->string('unique_token', 100);
    $table->ipAddress('user_ip')->nullable();

    $table->string('type', 32)->nullable();
    $table->string('agent', 256)->nullable();

    $table->timestamp('logged_at');
```
 #### Конфигурация

**config/auth.php**

```php
 ['providers' => [
        'users' => [  // название вашего провайдера, можете указать любое, главное что бы оно же было в секции "guards"
            'driver' => 'eloquent-tokens', // обязательно укажите название драйвера "eloquent-tokens"
            'models' => [
                'user' => App\Models\User::class, // модель, в которой хрянятся пользоавтели
                'token' => App\Models\UserToken::class, // модель, в которой хрянятся токены пользователей
            ],
        ],
    ],
]
```