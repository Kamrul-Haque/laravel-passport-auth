# laravel-passport-auth

[![Latest Stable Version](http://poser.pugx.org/kamrul-haque/laravel-passport-auth/v)](https://packagist.org/packages/kamrul-haque/laravel-passport-auth) [![Total Downloads](http://poser.pugx.org/kamrul-haque/laravel-passport-auth/downloads)](https://packagist.org/packages/kamrul-haque/laravel-passport-auth) [![Latest Unstable Version](http://poser.pugx.org/kamrul-haque/laravel-passport-auth/v/unstable)](https://packagist.org/packages/kamrul-haque/laravel-passport-auth) [![License](http://poser.pugx.org/kamrul-haque/laravel-passport-auth/license)](https://packagist.org/packages/kamrul-haque/laravel-passport-auth) ![GitHub Repo stars](https://img.shields.io/github/stars/Kamrul-Haque/laravel-passport-auth?color=F4BD16)

Authentication functionality for API using Laravel Passport

## Prerequisite

Install and configure [Laravel Passpost](https://laravel.com/docs/9.x/passport)

## Installation

Install the package via [composer](https://getcomposer.org/):
```
composer require kamrul-haque/laravel-passport-auth
```

Publish package resources:
```
php artisan vendor:publish --tag="laravel-passport-auth"
```

Migrate the necessary database tables:
```
php artisan migrate
```

## Configuration

Set the required configuration in ``.env``.
```
// .env

FRONTEND_URL=
FRONTEND_IP=
TOKEN_EXPIRY_DAYS=
TOKEN_REFRESH_EXPIRY_DAYS=
```

## Usage:

Add ``routes`` in ``api.php``:
```
// routes/api.php

include __DIR__ . '/passport.php';
```

Protect ``routes``:
```
// routes/api.php

Route::group(['middleware' => 'auth:api'], function () {
  // your routes
});
```

Register ``middleware`` in ``app\Http\Kernel.php`` inside ``$routeMiddleware`` array if you want to restrict API calls from certain IP address:
```
// app\Http\Kernel.php

protected $routeMiddleware = [
  // existing middlewares

  'restrict-request-ip' => \App\Http\Middleware\RestrictRequestIP::class,
];
```

Assign the ``middleware`` to ``routes``:
```
// routes/api.php

Route::group(['middleware' => 'restrict-request-ip'], function () {
  // your routes
});
```
