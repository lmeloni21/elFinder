<?php

use Rector\Config\RectorConfig;
use Rector\Php54\Rector\Array_\LongArrayToShortArrayRector;

return RectorConfig::configure()
    ->withPaths([__DIR__ . '/php'])
    ->withFileExtensions(['php', 'php-dist'])
    ->withPhpSets()
    ->withPHPStanConfigs([__DIR__ . '/rector-phpstan.neon'])
    ->withSkip([
        // Keep array formatting out of the runtime migration.
        LongArrayToShortArrayRector::class,
        // Remote drivers are extension points; inferred never would prevent subclasses implementing operations.
        \Rector\TypeDeclaration\Rector\ClassMethod\ReturnNeverTypeRector::class,
        // Preserve extension constructor layouts; Rector 2.8 trips on legacy parameter comments.
        \Rector\Php80\Rector\Class_\ClassPropertyAssignToConstructorPromotionRector::class,
        // Event unbind compares array callbacks; fresh Closure instances break identity.
        \Rector\Php81\Rector\Array_\ArrayToFirstClassCallableRector::class,
        \Rector\CodingStyle\Rector\FuncCall\FunctionFirstClassCallableRector::class,
        __DIR__ . '/php/connector.php',
        __DIR__ . '/php/connector.minimal.php',
    ]);
