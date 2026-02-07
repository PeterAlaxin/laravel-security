<?php

namespace PeterAlaxin\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class BlockedIp extends Model
{
    protected $fillable = [
        'ip',
        'reason',
        'attempts',
        'queued_at',
        'blocked_at',
    ];

    protected function casts(): array
    {
        return [
            'queued_at' => 'datetime',
            'blocked_at' => 'datetime',
        ];
    }

    public function scopeQueued(Builder $query): Builder
    {
        return $query->whereNull('blocked_at');
    }

    public function scopeBlocked(Builder $query): Builder
    {
        return $query->whereNotNull('blocked_at');
    }
}
