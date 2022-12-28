# laravel-passport-auth

Authentication functionality for API using Laravel Passport

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
