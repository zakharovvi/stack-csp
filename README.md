# Stack-CSP

[Stack](http://stackphp.com/) middleware for generating Content Security Policy ([CSP 1.0](http://www.w3.org/TR/CSP/)) HTTP headers for the request

## Usage

### Setting a default CSP

If preferred you can pass a default set of policy rules to be served, which can be overwritten or appended to. The provider accepts an array of CSP directives with a single value or an array of values passed via a `enforce` array.

If testing out a new CSP you want to make sure it does not break the site. You will want to issue a `Content-Security-Policy-Report-Only` HTTP header to have the user agent report violations to the `report-uri` for review, but not to enforce it. You can issue this type of CSP alongside an already active one by using a `report` array.

```php
$app = new Silex\Application();

$cspPolicy = new KyraD\Stack\Csp\Config([
    'enforce' => [
        'script-src' => ['none'],
        'font-src'   => 'self',
        'report-uri' => ['/report', 'http://www.example.com'],
        'sandbox'    => ['allow-forms', 'allow-scripts']
    ],
    'report' => [
        'script-src' => ['self', 'http://www.example.com', 'unsafe-inline'],
        'font-src'   => 'self',
        'report-uri' => ['/report', 'http://www.example.com'],
        'sandbox'    => ['allow-forms', 'allow-scripts']
    ]
]);

$app->get('...', function(Request $request, Application $app) {
    // ...
});

$app = new KyraD\Stack\Csp($app, $cspPolicy);

Stack\run($app);
```

**Note:** If no default policy is set then no CSP headers are sent globally. In which case you can add a policy rule from a route, and the CSP header will only be sent for that specific route.

### Adding CSP Policy Rule(s)

To add additional rules to a policy per route *(if a default policy is provided)*, or to create a new one if not, you would do the following:

```php
$app->get('...', function (Application $app) {
    // ...
})->value('cspAdd', [
    'enforce' => [
        'script-src' => ['http://cn1.example.com']
    ],
    'report' => [
        'style-src' => ['http://www.example.com']
    ]
]);
```

### Removing CSP Policy Rule(s)

If you want to remove specific policy rules you would do the following. If a value for a directive is found that matches current policy it will be removed.

```php
$app->get('...', function (Application $app) {
    // ...
})->value('cspRemove', [
    'enforce' => [
        'script-src' => ['http://cdn2.example.com'],
        'report-uri' => ['http://example.com:8000'],
        'sandbox'    => ['allow-forms']
    ],
    'report' => [
        'style-src' => ['http://www.google.com'],
        'sandbox'   => ['allow-forms']
    ]
]);
```

### Clearing CSP Policies

To clear a CSP policy for a route and effectively start to build off an empty policy, you would do the following. This is also how you would completely disable CSP for a route if needed to do so.

```php
$app->get('/', function (Application $app) {
    return new Response('');
})->value('cspReset', 'enforce');
```
Values accepted for `Policy::cspReset` are `enforce`, `report` and `all`.

### Caveats
#### Symfony Web Profiler

If using the profiler with an `enforce` policy you must allow the following as it inserts JavaScript and CSS into the document. Development sites SHOULD be using a `report-only` policy which SHOULD be made `enforce` when moving to production.

```
script-src 'unsafe-eval' 'unsafe-inline'
style-src 'unsafe-inline'
```

> **Warning:** If enabling these settings you MUST make sure you remove it when moving to production as it will otherwise disable XSS protection.

#### GreaseMonkey

Badly configured GreaseMonkey scripts will load into the global space causing a policy violation if `unsafe-inline` and/or `unsafe-eval` is not set. Nothing can be done to prevent it as it is out of the control of the server.

#### Browsers

Content Security Policy 1.0 is still being integrated into modern browsers, and as such will have some differences among the implementations.

##### Firefox

Firefox 4+ does not support the `sandbox` directive. It will be ignored, and invoke a warning in the console. All other directives will be processed.

Prior to Firefox 23, the `xhr-src` directive was used in place of the `connect-src` directive and only restricted the use of XMLHttpRequest.

##### Internet Explorer 10+

Only supports the `sandbox` directive. All other directives will be ignored.

### Credits

A big thanks for code contributions, peer reviewing, and general help to the following individuals, and anyone else I may have forgot.

[@datibbaw](https://github.com/datibbaw), [@krakjoe](https://github.com/krakjoe), [@Hamz-a](https://github.com/Hamz-a), [@igorw](https://github.com/igorw), [@Ocramius](https://gist.github.com/Ocramius), [@rdlowrey](https://github.com/rdlowrey), [@teresko](https://github.com/teresko), [@webarto](https://github.com/webarto)
