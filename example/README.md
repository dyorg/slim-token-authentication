# Slim Token Authentication Example

This is a simple example of how implements token authentication with Slim application.
See complete documentation on [Slim Token Authentication](https://github.com/dyorg/slim-token-authentication).

## Installing dependencies

```bash
composer install
```

## Setting example root directory

If you are using virtual hosts, do you should setting the `/example` directory as root.   
Code below shows the code pointing to the right path. 

```bash
<VirtualHost *:80> 
    DocumentRoot "C:/laragon/www/slim-token-authentication/example"
    ServerName slim-token-authentication.local
    ServerAlias *.slim-token-authentication.local
    <Directory "C:/laragon/www/slim-token-authentication/example">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

Otherwise, without virtual host, do you could access through `http://localhost/`.

```bash 
http://localhost/slim-token-authentication/example/
``` 

## Making authentication with header

On your prompt via curl:

```bash
$ curl -i http://slim-token-authentication.local/restrict -H "Authorization: Bearer usertokensecret"
```

## Making authentication with query paramater

On your prompt:

```bash
$ curl -i http://slim-token-authentication.local/restrict?authorization=usertokensecret
```

Instead you can try authentication with parameter via your browser:

```bash
http://localhost/slim-token-authentication/example/restrict?authorization=usertokensecret
```

## Responses

On success should return something like:

```bash
HTTP/1.1 200 OK
Date: Fri, 24 Aug 2018 16:56:57 GMT
Server: Apache/2.4.27 (Win64) OpenSSL/1.0.2l PHP/7.1.7
X-Powered-By: PHP/7.1.7
Content-Length: 70
Content-Type: application/json;charset=utf-8

{
    "message": "It's a restrict area. Token authentication works!"
}
```

With wrong token should return something like:

```bash
HTTP/1.1 401 Unauthorized
Date: Fri, 24 Aug 2018 16:55:16 GMT
Server: Apache/2.4.27 (Win64) OpenSSL/1.0.2l PHP/7.1.7
X-Powered-By: PHP/7.1.7
Content-Length: 65
Content-Type: application/json;charset=utf-8

{
    "message": "Invalid Token",
    "token": "usertokenwrong"
}
```

