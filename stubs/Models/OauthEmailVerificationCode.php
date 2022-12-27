<?php

namespace Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class OauthEmailVerificationCode extends Model
{
    protected $guarded = [];

    public static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            $model->code = random_int(100000, 999999);
            $model->expire_at = now()->addMinutes(5);
            $model->token = Str::uuid();
        });
    }
}
