# Como habilitar mod_headers no Apache Ubuntu

<p style='text-align: justify;'>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
O módulo <i><b>mod_headers</b></i> é muito útil, permite ao Apache controlar e modificar os cabeçalhos de solicitação e resposta <i>HTTP</i> no Apache. Se você tentar modificar os cabeçalhos no servidor da web Apache sem instalar <i><b>mod_headers</b></i>, pode ocorrer um erro interno do servidor. Veja como habilitar mod_headers no Apache <i>Ubuntu/Debian</i>. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Você também pode usá-lo para habilitar mod_headers no Cpanel, WordPress. No entanto, o mod_headers já está instalado em httpd no Redhat/Fedora/CentOS, por padrão. 
</p>

## Instale mod_headers

Se você deseja instalar o módulo Apache, como <i><b>mod_headers</b></i>, você precisa emitir o comando <i><b>a2enmod</b></i>.

```bash
$ sudo a2enmod <module_name>
``` 
Para ativar o módulo:

```bash
$ sudo a2enmod headers
```

 ## Reinicie o Apache Web Server

 Reinicie o servidor da web Apache para que as alterações tenham efeito.

 ```bash
 $ sudo systemctl restart apache2.service 
 ```
## Verifique se mod_headers está funcionando

Você pode verificar facilmente se <i><b>mod_headers</i></b> está habilitado executando o seguinte comando:

```bash
$ sudo apachectl -M |grep header
 
 headers_module (shared)

```

---
# Arquivo de configuração servidor Tomcat

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
<!-- Note:  A "Server" is not itself a "Container", so you may not
define subcomponents such as "Valves" at this level.
Documentation at /docs/config/server.html
-->
<Server port="-1" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <!-- Security listener. Documentation at /docs/config/listeners.html
  <Listener className="org.apache.catalina.security.SecurityListener" />
  -->
  <!--APR library loader. Documentation at /docs/apr.html -->
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" />
  <!-- Prevent memory leaks due to use of particular java/javax APIs-->
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />

  <!-- Global JNDI resources
       Documentation at /docs/jndi-resources-howto.html
  -->
  <GlobalNamingResources>
    <!-- Editable user database that can also be used by
         UserDatabaseRealm to authenticate users
    -->
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              description="User database that can be updated and saved"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>

  <!-- A "Service" is a collection of one or more "Connectors" that share
       a single "Container" Note:  A "Service" is not itself a "Container",
       so you may not define subcomponents such as "Valves" at this level.
       Documentation at /docs/config/service.html
   -->
  <Service name="Catalina">

    <!--The connectors can use a shared executor, you can define one or more named thread pools-->
    <!--
    <Executor name="tomcatThreadPool" namePrefix="catalina-exec-"
        maxThreads="150" minSpareThreads="4"/>
    -->


    <!-- A "Connector" represents an endpoint by which requests are received
         and responses are returned. Documentation at :
         Java HTTP Connector: /docs/config/http.html
         Java AJP  Connector: /docs/config/ajp.html
         APR (HTTP/AJP) Connector: /docs/apr.html
         Define a non-SSL/TLS HTTP/1.1 Connector on port 8080
    -->
    <Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />
    <!-- A "Connector" using the shared thread pool-->
    <!--
    <Connector executor="tomcatThreadPool"
               port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />
    -->
    <!-- Define an SSL/TLS HTTP/1.1 Connector on port 8443
         This connector uses the NIO implementation. The default
         SSLImplementation will depend on the presence of the APR/native
         library and the useOpenSSL attribute of the
         AprLifecycleListener.
         Either JSSE or OpenSSL style configuration may be used regardless of
         the SSLImplementation selected. JSSE style configuration is used below.
    -->

    <!--
    <Connector
            protocol="org.apache.coyote.http11.Http11NioProtocol"
            port="443" maxThreads="200"
            scheme="https" secure="true" SSLEnabled="true"
            keystoreFile="/etc/letsencrypt/live/www309.dominio.com/bundle.pfx" keystorePass="321654"
            clientAuth="false" sslProtocol="TLS" keystoreType="PKCS12"/>

    -->
            <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol" maxThreads="150" SSLEnabled="true" >
            <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
            <SSLHostConfig>
            <Certificate certificateKeyFile="/etc/tomcat9/cert/private.key" certificateFile="/etc/tomcat9/cert/certificate.crt" certificateChainFile="/etc/tomcat9/cert/ca_bundle.crt" type="RSA" />
            </SSLHostConfig>
            </Connector>
    <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="conf/localhost-rsa.jks"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
    -->
    <!-- Define an SSL/TLS HTTP/1.1 Connector on port 8443 with HTTP/2
         This connector uses the APR/native implementation which always uses
         OpenSSL for TLS.
         Either JSSE or OpenSSL style configuration may be used. OpenSSL style
         configuration is used below.
    -->
    <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true" >
        <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
        <SSLHostConfig>
            <Certificate certificateKeyFile="conf/localhost-rsa-key.pem"
                         certificateFile="conf/localhost-rsa-cert.pem"
                         certificateChainFile="conf/localhost-rsa-chain.pem"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
    -->

    <!-- Define an AJP 1.3 Connector on port 8009 -->
    <!--
    <Connector protocol="AJP/1.3"
               address="::1"
               port="8009"
               redirectPort="8443" />
    -->

    <!-- An Engine represents the entry point (within Catalina) that processes
         every request.  The Engine implementation for Tomcat stand alone
         analyzes the HTTP headers included with the request, and passes them
         on to the appropriate Host (virtual host).
         Documentation at /docs/config/engine.html -->

    <!-- You should set jvmRoute to support load-balancing via AJP ie :
    <Engine name="Catalina" defaultHost="localhost" jvmRoute="jvm1">
    -->
    <Engine name="Catalina" defaultHost="localhost">

      <!--For clustering, please take a look at documentation at:
          /docs/cluster-howto.html  (simple how to)
          /docs/config/cluster.html (reference documentation) -->
      <!--
      <Cluster className="org.apache.catalina.ha.tcp.SimpleTcpCluster"/>
      -->

      <!-- Use the LockOutRealm to prevent attempts to guess user passwords
           via a brute-force attack -->
      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <!-- This Realm uses the UserDatabase configured in the global JNDI
             resources under the key "UserDatabase".  Any edits
             that are performed against this UserDatabase are immediately
             available for use by the Realm.  -->
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>

      <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">

        <!-- SingleSignOn valve, share authentication between web applications
             Documentation at: /docs/config/valve.html -->
        <!--
        <Valve className="org.apache.catalina.authenticator.SingleSignOn" />
        -->

        <!-- Access log processes all example.
             Documentation at: /docs/config/valve.html
             Note: The pattern used is equivalent to using pattern="common" -->
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />

      </Host>
    </Engine>
  </Service>
</Server>
```
# Pacotes para instalar
```bash
apt install certbot httpry
a2enmod proxy  proxy_http

vim sites-available/000-default.conf 
```
# Arquivos de configuração apache2
```apache
<VirtualHost www22.dominnio.com:80>
        ServerName dominio.com
        ServerAlias www22.dominio.com

        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
#RewriteEngine on
#RewriteCond %{SERVER_NAME} =dominio.com [OR]
#RewriteCond %{SERVER_NAME} =www22.dominio.com
#RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
        ProxyPreserveHost On
        ProxyPass / http://192.168.4.193:8080/guacamole/
        ProxyPassReverse / http://192.168.4.193:8080/guacamole/
</VirtualHost>

<VirtualHost srv309.dominio.com:80>
        ServerName dominio.com
        ServerAlias srv309.dominio.com

        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
#RewriteEngine on
#RewriteCond %{SERVER_NAME} =www309.dominio.com [OR]
#RewriteCond %{SERVER_NAME} =dominio.com
#RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

```bash
$ vim sites-available/000-default-le-ssl.conf 
```

```apache
<IfModule mod_ssl.c>
<VirtualHost www309.dominio.com:443>
        ServerName dominio.com
        ServerAlias www309.dominio.com

        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf

        ProxyPreserveHost On
        ProxyPass / https://192.168.4.193:8443/guacamole/
        ProxyPassReverse / https://192.168.4.193:8443/guacamole/

SSLCertificateFile /etc/letsencrypt/live/www309.dominio.com/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/www309.dominio.com/privkey.pem
Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>
<IfModule mod_ssl.c>
<VirtualHost www22.dominio.com:443>
        ServerName dominio.com
        ServerAlias www22.dominio.com

        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf

        ProxyPreserveHost On
#       ProxyPass / https://192.168.4.193:8443/guacamole/
#       ProxyPassReverse / https://192.168.4.193:8443/guacamole/

        # HSTS (optional)
        Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"
        # Remove this if you need to use frames or iframes
        Header always set X-Frame-Options DENY
        # Prevent MIME based attacks
        Header set X-Content-Type-Options "nosniff"
       
        # Reverse proxy configuration
        <Location />
                ProxyPass http://localhost:8080/guacamole/
                ProxyPassReverse http://localhost:8080/guacamole/
        </Location>

SSLCertificateFile /etc/letsencrypt/live/www309.dominio.com/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/www309.dominio.com/privkey.pem
Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>

```

---
# Links de referência
[Como instalar o Tomcat no Ubuntu e derivados?](https://ubunlog.com/pt/como-instalar-tomcat-en-ubuntu-y-derivados/)</br>
[Customizar tomcat 8](http://blog.aeciopires.com/customizando-o-tomcat-8/)</br>
[Documentação Tomcat 9](https://tomcat.apache.org/tomcat-9.0-doc/ssl-howto.html#Configuration) </br>
[How to install lets encrypt with tomcat](https://medium.com/@raupach/how-to-install-lets-encrypt-with-tomcat-3db8a469e3d2) </br>
[Guia passo-a-passo LetsEncrypt ou Qualquer Certificado SSL](https://medium.com/@mashrur123/a-step-by-step-guide-to-securing-a-tomcat-server-with-letsencrypt-ssl-certificate-65cd26290b70)</br>
[Como instalar Apache Tomcat 9 no Ubuntu 18.04](https://www.digitalocean.com/community/tutorials/install-tomcat-9-ubuntu-1804-pt) </br>
[Instale um certificado SSL grátis Let's Encrypt para Tomcat Server no Ubuntu](https://o7planning.org/12243/install-a-free-ssl-certificate-lets-encrypt-for-tomcat-server-on-ubuntu)</br>
[Certbot error: Problem binding to port 80](https://www.linode.com/community/questions/18963/certbot-error-problem-binding-to-port-80)</br>
[Installing SSL Certificate on Tomcat](https://help.zerossl.com/hc/en-us/articles/360060120393-Installing-SSL-Certificate-on-Tomcat)</br>
[A Step-By-Step Guide to Securing a Tomcat Server With LetsEncrypt or Any SSL Certificate](https://medium.com/@mashrur123/a-step-by-step-guide-to-securing-a-tomcat-server-with-letsencrypt-ssl-certificate-65cd26290b70)</br>
[How to Install Tomcat 8 on Ubuntu 18.04/16.04 LTS](https://www.fosstechnix.com/install-tomcat-8-on-ubuntu/) </br>
[How to Enable mod_headers in Apache Ubuntu](https://ubiq.co/tech-blog/enable-mod_headers-apache-ubuntu/)</br>
[Lets encrypt SSL certificate on tomcat @icn-camera](https://www.youtube.com/watch?v=IE7eQQc1S1Y)</br>
[How To Secure Apache with Let's Encrypt on Ubuntu 20.04](https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-20-04)</br>
[How to install Let’s Encrypt on Apache2](https://upcloud.com/community/tutorials/install-lets-encrypt-apache/)<br>
[Documentação Apache Proxy Reverso](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html)</br>
[Configurando Proxy Reverso no Apache](https://fassi.tec.br/2020/08/configurando-proxy-reverso-no-apache/)</br>
[Apache2 como Proxy Reverso](https://www.centosblog.com/configure-apache-https-reverse-proxy-centos-linux/)</br>
[Como configurar o Apache como Proxy Reverso no Linux](https://mateusmuller.me/2018/10/11/como-configurar-o-apache-como-proxy-reverso-no-linux/)</br>

