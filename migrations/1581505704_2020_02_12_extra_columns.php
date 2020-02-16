<?php

use October\Rain\Database\Updates\Migration;
use October\Rain\Database\Schema\Blueprint;

class ExtraColumns extends Migration
{
    public function up()
    {
        if (! Schema::hasColumn('backend_users', 'tfa_is_opened')) {
            Schema::table('backend_users', function(Blueprint $table) {
                $table->boolean('tfa_is_opened')->default(0);
            });
        }

        if (! Schema::hasColumn('backend_users', 'tfa_secret_key')) {
            Schema::table('backend_users', function(Blueprint $table) {
                $table->string('tfa_secret_key', 200)->nullable();
            });
        }

        if (! Schema::hasColumn('backend_users', 'tfa_is_authenticated')) {
            Schema::table('backend_users', function(Blueprint $table) {
                $table->boolean('tfa_is_authenticated')->default(0);
            });
        }
    }

    public function down()
    {
        if (Schema::hasColumn('backend_users', 'tfa_is_opened')) {
            Schema::table('backend_users', function(Blueprint $table) {
                $table->dropColumn('tfa_is_opened');
            });
        }

        if (Schema::hasColumn('backend_users', 'tfa_secret_key')) {
            Schema::table('backend_users', function(Blueprint $table) {
                $table->dropColumn('tfa_secret_key');
            });
        }

        if (Schema::hasColumn('backend_users', 'tfa_is_authenticated')) {
            Schema::table('backend_users', function(Blueprint $table) {
                $table->dropColumn('tfa_is_authenticated');
            });
        }
    }
}
