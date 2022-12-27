<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateOauthEmailVerificationCodesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('oauth_email_verification_codes', function (Blueprint $table) {
            $table->id();
            $table->integer('code')->unsigned();
            $table->string('email');
            $table->string('token');
            $table->boolean('is_verified')->default(false);
            $table->timestamp('expire_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('oauth_email_verification_codes');
    }
}
