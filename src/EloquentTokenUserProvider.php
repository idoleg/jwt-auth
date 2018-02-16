<?php
/**
 * Created by PhpStorm.
 * User: olegs
 * Date: 16.02.2018
 * Time: 0:20
 */

namespace Idoleg\JwtAuth;


use Illuminate\Support\Str;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;


class EloquentTokenUserProvider implements UserProvider
{

    /**
     * The hasher implementation.
     *
     * @var \Illuminate\Contracts\Hashing\Hasher
     */
    protected $hasher;

    /**
     * The Eloquent user model.
     *
     * @var string
     */
    protected $userModel;

    /**
     * The Eloquent token model.
     *
     * @var string
     */
    protected $tokenModel;

    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher $hasher
     * @param  string $model
     * @return void
     */
    public function __construct(HasherContract $hasher, $userModel, $tokenModel)
    {
        $this->userModel = $userModel;
        $this->tokenModel = $tokenModel;
        $this->hasher = $hasher;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        $userModel = $this->createModel();

        return $userModel->newQuery()
            ->where($userModel->getAuthIdentifierName(), $identifier)
            ->first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed $identifier
     * @param  string $token
     * @param  string $uip User IP address
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token, $uip = null)
    {
        $tokenModel = $this->createTokenModel();

        $tokenModel = $tokenModel->where('user_id', $identifier)->where('remember_token', $token)->first();;

        if (!$tokenModel) {
            return null;
        }

        if (!empty($uip)) {
//            $ipFromModel = $model->ip;
            if (isset($tokenModel->user_ip) and $tokenModel->user_ip !== $uip) {
                return null;
            }
        }

        $userModel = $this->createModel();
        return $userModel->newQuery()
            ->where($userModel->getAuthIdentifierName(), $tokenModel->user_id)
            ->first();
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  string $token
     * @param null $uip
     * @param null $type
     * @param null $agent
     * @param null $logged_at
     * @return void
     */
    public function updateRememberToken(UserContract $user, $token, $uip = null, $type = null, $agent = null, $logged_at = null)
    {
        $tokenModel = $this->createTokenModel();

        $tokenModel->user_id = $user->getAuthIdentifier();
        $tokenModel->remember_token = $token;

        if (!empty($uip)) $tokenModel->user_ip = $uip;
        if (!empty($type)) $tokenModel->type = $type;
        if (!empty($agent)) $tokenModel->agent = $agent;

        $tokenModel->logged_at = $logged_at ?? time();

        $tokenModel->save();
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials) ||
            (count($credentials) === 1 &&
                array_key_exists('password', $credentials))) {
            return;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // Eloquent User "model" that will be utilized by the Guard instances.
        $query = $this->createModel()->newQuery();

        foreach ($credentials as $key => $value) {
            if (!Str::contains($key, 'password')) {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  array $credentials
     * @return bool
     */
    public function validateCredentials(UserContract $user, array $credentials)
    {
        $plain = $credentials['password'];

        return $this->hasher->check($plain, $user->getAuthPassword());
    }

    /**
     * Create a new instance of the model.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function createModel()
    {
        $class = '\\' . ltrim($this->userModel, '\\');

        return new $class;
    }

    /**
     * Create a new instance of the model.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function createTokenModel()
    {
        $class = '\\' . ltrim($this->tokenModelModel, '\\');

        return new $class;
    }

    /**
     * Gets the hasher implementation.
     *
     * @return \Illuminate\Contracts\Hashing\Hasher
     */
    public function getHasher()
    {
        return $this->hasher;
    }

    /**
     * Sets the hasher implementation.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher $hasher
     * @return $this
     */
    public function setHasher(HasherContract $hasher)
    {
        $this->hasher = $hasher;

        return $this;
    }

    /**
     * Gets the name of the Eloquent user model.
     *
     * @return string
     */
    public function getModel()
    {
        return $this->userModel;
    }

    /**
     * Sets the name of the Eloquent user model.
     *
     * @param  string $userModel
     * @return $this
     */
    public function setModel($userModel)
    {
        $this->userModel = $userModel;

        return $this;
    }

}