Hi,team,we found some security issues via security software as the follow.hope can fix it on  next version.thx. 






Name	Synopsis	Description	Solution	See Also
Missing Content Security Policy	Missing Content Security Policy	Content Security Policy (CSP) is a web security standard that helps to mitigate attacks like cross-site scripting (XSS), clickjacking or mixed content issues. CSP provides mechanisms to websites to restrict content that browsers will be allowed to load.

No CSP header has been detected on this host. This URL is flagged as a specific example.	Configure Content Security Policy on your website by adding 'Content-Security-Policy' HTTP header or meta tag http-equiv='Content-Security-Policy'.	https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

https://csp-evaluator.withgoogle.com/

https://content-security-policy.com/

https://developers.google.com/web/fundamentals/security/csp/

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
Password Field With Auto-Complete	Password Field With Auto-Complete	In typical form-based web applications, it is common practice for developers to allow `autocomplete` within the HTML form to improve the usability of the page. With `autocomplete` enabled (default), the browser is allowed to cache previously entered form values.

For legitimate purposes, this allows the user to quickly re-enter the same data when completing the form multiple times.

When `autocomplete` is enabled on either/both the username and password fields, this could allow a cyber-criminal with access to the victim's computer the ability to have the victim's credentials automatically entered as the cyber-criminal visits the affected page.

Scanner has discovered that the affected page contains a form containing a password field that has not disabled `autocomplete`.	The `autocomplete` value can be configured in two different locations.
The first and most secure location is to disable the `autocomplete` attribute on the `<form>` HTML tag. This will disable `autocomplete` for all inputs within that form. An example of disabling `autocomplete` within the form tag is `<form autocomplete=off>`.
The second slightly less desirable option is to disable the `autocomplete` attribute for a specific `<input>` HTML tag. While this may be the less desired solution from a security perspective, it may be preferred method for usability reasons, depending on size of the form. An example of disabling the `autocomplete` attribute within a password input tag is `<input type=password autocomplete=off>`.	https://www.owasp.org/index.php/Testing_for_Vulnerable_Remember_Password_(OTG-AUTHN-005)
Permissive Content Security Policy Detected	Permissive Content Security Policy Detected	Content Security Policy (CSP) is a web security standard that helps to mitigate attacks like cross-site scripting (XSS), clickjacking or mixed content issues. CSP provides mechanisms to websites to restrict content that browsers will be allowed to load.

One or several permissive directives have been detected. See output for more details.	The following directive configurations can be applied to have a safe content security policy:

- 'frame-ancestors' should be set to 'none' to avoid rendering of page in <frame>, <iframe>, <object>, <embed>, or <applet>.
- 'form-action' should be explicitly set to 'self' to restrict form submission to the origin which the protected page is being served.
- 'upgrade-insecure-requests' and 'block-all-mixed-content' should be set to avoid mixed content (URLs served over HTTP and HTTPS) on the page.
- Any of the 'unsafe-*' directives indicate that the action is considered unsafe & it is better to refactor the code to avoid using HTML event handlers that rely on this.
- data: https: http: URI in 'default-src', 'object-src', 'base-uri' & 'script-src' allow execution of unsafe scripts and should not be set.
- * and *.* in 'script-src' and other '-src' directives allows execution of unsafe scripts and should be restricted.
- 'default-src' should be explicitly set to 'self' or 'none' and individual directives required for each source type set more permissively as required
- * and *.* in 'default-src' allows various unconfigured parameters to default to a unsafe configuration and then should not be set.
- none, unsafe-eval, unsafe-inline and self keywords require wrapping with single quotations to be valid
- 'object-src' should be explicitly set to 'none' to avoid execution of unsafe scripts.
 
If these directives are required for business continuity in your environment, apply mitigating controls suitable for your environment and work with the vendors of the products for which these directives are required.	https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

https://csp-evaluator.withgoogle.com/

https://content-security-policy.com/

https://developers.google.com/web/fundamentals/security/csp/

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
Missing Content Security Policy	Missing Content Security Policy	Content Security Policy (CSP) is a web security standard that helps to mitigate attacks like cross-site scripting (XSS), clickjacking or mixed content issues. CSP provides mechanisms to websites to restrict content that browsers will be allowed to load.

No CSP header has been detected on this host. This URL is flagged as a specific example.	Configure Content Security Policy on your website by adding 'Content-Security-Policy' HTTP header or meta tag http-equiv='Content-Security-Policy'.	https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

https://csp-evaluator.withgoogle.com/

https://content-security-policy.com/

https://developers.google.com/web/fundamentals/security/csp/

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
Missing Content Security Policy	Missing Content Security Policy	Content Security Policy (CSP) is a web security standard that helps to mitigate attacks like cross-site scripting (XSS), clickjacking or mixed content issues. CSP provides mechanisms to websites to restrict content that browsers will be allowed to load.

No CSP header has been detected on this host. This URL is flagged as a specific example.	Configure Content Security Policy on your website by adding 'Content-Security-Policy' HTTP header or meta tag http-equiv='Content-Security-Policy'.	https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

https://csp-evaluator.withgoogle.com/

https://content-security-policy.com/

https://developers.google.com/web/fundamentals/security/csp/

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
SQL Statement Disclosure	SQL Statement Disclosure	Web applications usually rely on backend database servers to store persistent information like users, sessions or for example products of an e-commerce website. In some cases, these web applications may fail to properly handle potential errors raised when querying the database, displaying raw errors or stack traces.

Exposed information may leak sensitive information (for example session tokens used in a statement) or help an attacker conducting further attacks like SQL injections.	Ensure that the potential SQL errors and exceptions are caught and handled by the web applications to avoid displaying raw error messages. The SQL statement disclosed should also be verified to ensure that SQL injections cannot occur from unsanitized user inputs.	https://owasp.org/www-community/Improper_Error_Handling

https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
Disclosed European Personal Data Number	Disclosed European Personal Data Number	A European Personal Data Number (EPDN) is a personally identifiable number that is issued to a citizen of one of the members or ex-members of the European Union. A stolen or leaked EPDN can lead to a compromise, and/or the theft of the affected individuals identity. WAS has discovered an EPDN located within the response of the affected page	Initially, the Identified EPDN within the response should be checked to ensure its validity, as it is possible that the regular expression has matched on a similar number with no relation to a real EPDN due to the wide variety of formats across the region. If the response does contain a valid EPDN, then all efforts should be taken to remove or further protect this information. This can be achieved by removing the EPDN altogether, or by masking the number so that only a few digits are present within the response. (eg. _*****123*****_).	https://en.wikipedia.org/wiki/National_identity_cards_in_the_European_Economic_Area#Overview_of_national_identity_cards

https://www.liquisearch.com/national_identification_number

https://ipsec.pl/european-personal-data-regexp-patterns.html
Credit Card Number Disclosure	Credit Card Number Disclosure	Credit card numbers are used in applications where a user is able to purchase goods and/or services.

A credit card number is a sensitive piece of information and should be handled as such. Cyber-criminals will use various methods to attempt to compromise credit card information that can then be used for fraudulent purposes.

Through the use of regular expressions and CC number format validation using known issuer numbers and luhn check validation, the scanner was able to discover a credit card number located within the affected page.	Initially, the credit card number within the response should be checked to ensure its validity, as it is possible that the regular expression has matched on a similar number with no relation to a real credit card.
If the response does contain a valid credit card number, then all efforts should be taken to remove or further protect this information. This can be achieved by removing the credit card number altogether, or by masking the number so that only the last few digits are present within the response. (eg. _**********123_).
Additionally, credit card numbers should not be stored by the application, unless the organisation also complies with other security controls as outlined in the Payment Card Industry Data Security Standard (PCI DSS).	http://en.wikipedia.org/wiki/Bank_card_number

http://en.wikipedia.org/wiki/Luhn_algorithm

https://gist.github.com/1182499
Password Field With Auto-Complete	Password Field With Auto-Complete	In typical form-based web applications, it is common practice for developers to allow `autocomplete` within the HTML form to improve the usability of the page. With `autocomplete` enabled (default), the browser is allowed to cache previously entered form values.

For legitimate purposes, this allows the user to quickly re-enter the same data when completing the form multiple times.

When `autocomplete` is enabled on either/both the username and password fields, this could allow a cyber-criminal with access to the victim's computer the ability to have the victim's credentials automatically entered as the cyber-criminal visits the affected page.

Scanner has discovered that the affected page contains a form containing a password field that has not disabled `autocomplete`.	The `autocomplete` value can be configured in two different locations.
The first and most secure location is to disable the `autocomplete` attribute on the `<form>` HTML tag. This will disable `autocomplete` for all inputs within that form. An example of disabling `autocomplete` within the form tag is `<form autocomplete=off>`.
The second slightly less desirable option is to disable the `autocomplete` attribute for a specific `<input>` HTML tag. While this may be the less desired solution from a security perspective, it may be preferred method for usability reasons, depending on size of the form. An example of disabling the `autocomplete` attribute within a password input tag is `<input type=password autocomplete=off>`.	https://www.owasp.org/index.php/Testing_for_Vulnerable_Remember_Password_(OTG-AUTHN-005)
Permissive Content Security Policy Detected	Permissive Content Security Policy Detected	Content Security Policy (CSP) is a web security standard that helps to mitigate attacks like cross-site scripting (XSS), clickjacking or mixed content issues. CSP provides mechanisms to websites to restrict content that browsers will be allowed to load.

One or several permissive directives have been detected. See output for more details.	The following directive configurations can be applied to have a safe content security policy:

- 'frame-ancestors' should be set to 'none' to avoid rendering of page in <frame>, <iframe>, <object>, <embed>, or <applet>.
- 'form-action' should be explicitly set to 'self' to restrict form submission to the origin which the protected page is being served.
- 'upgrade-insecure-requests' and 'block-all-mixed-content' should be set to avoid mixed content (URLs served over HTTP and HTTPS) on the page.
- Any of the 'unsafe-*' directives indicate that the action is considered unsafe & it is better to refactor the code to avoid using HTML event handlers that rely on this.
- data: https: http: URI in 'default-src', 'object-src', 'base-uri' & 'script-src' allow execution of unsafe scripts and should not be set.
- * and *.* in 'script-src' and other '-src' directives allows execution of unsafe scripts and should be restricted.
- 'default-src' should be explicitly set to 'self' or 'none' and individual directives required for each source type set more permissively as required
- * and *.* in 'default-src' allows various unconfigured parameters to default to a unsafe configuration and then should not be set.
- none, unsafe-eval, unsafe-inline and self keywords require wrapping with single quotations to be valid
- 'object-src' should be explicitly set to 'none' to avoid execution of unsafe scripts.
 
If these directives are required for business continuity in your environment, apply mitigating controls suitable for your environment and work with the vendors of the products for which these directives are required.	https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

https://csp-evaluator.withgoogle.com/

https://content-security-policy.com/

https://developers.google.com/web/fundamentals/security/csp/

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
SQL Statement Disclosure	SQL Statement Disclosure	Web applications usually rely on backend database servers to store persistent information like users, sessions or for example products of an e-commerce website. In some cases, these web applications may fail to properly handle potential errors raised when querying the database, displaying raw errors or stack traces.

Exposed information may leak sensitive information (for example session tokens used in a statement) or help an attacker conducting further attacks like SQL injections.	Ensure that the potential SQL errors and exceptions are caught and handled by the web applications to avoid displaying raw error messages. The SQL statement disclosed should also be verified to ensure that SQL injections cannot occur from unsanitized user inputs.	https://owasp.org/www-community/Improper_Error_Handling

https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
SSL/TLS Weak Cipher Suites Supported	SSL/TLS Weak Cipher Suites Supported	The remote host supports the use of SSL/TLS ciphers that offer weak encryption (including RC4 and 3DES encryption).	Reconfigure the affected application, if possible to avoid the use of weak ciphers.	https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
jQuery UI < 1.13.2 Cross-Site Scripting	jQuery UI < 1.13.2 Cross-Site Scripting	According to its self-reported version number, jQuery UI is prior to 1.13.2. It is, therefore, affected by a Cross-Site Scripting when refreshing a checkboxradio with an HTML-like initial text label (CVE-2022-31160)

Note that the scanner has not tested for these issues but has instead relied only on the application's self-reported version number.	Upgrade to jQuery UI version 1.13.2 or later.	https://blog.jqueryui.com/2022/07/jquery-ui-1-13-2-released/

https://github.com/jquery/jquery-ui/security/advisories/GHSA-h6gj-6jjq-h8g9
Login Form Cross-Site Request Forgery	Login Form Cross-Site Request Forgery	Cross Site Request Forgery (CSRF) occurs when an user is tricked into clicking on a link which would automatically submit a request without the user's consent.

This can be made possible when the request does not include an anti-CSRF token, generated each time the request is visited and passed when the request is submitted, and which can be used by the web application backend to verify that the request originates from a legitimate user.

Exploiting requests vulnerable to Cross-Site Request Forgery requires different factors:

- The request must perform a sensitive action.

- The attacker must make the victim click on a link to send the request without their consent.

The exploitation of this vulnerability will in most cases have a very limited impact. However, it is possible to create complex scenarios in case the application is also vulnerable to Cross-Site Scripting.	Update the application by adding support of anti-CSRF tokens on this login form.
Most web frameworks provide either built-in solutions or have plugins that can be used to easily add these tokens to any form. Check the references for possible solutions provided for the most known frameworks.	https://codex.wordpress.org/WordPress_Nonces

https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/csrf_paper.pdf

https://www.drupal.org/docs/7/security/writing-secure-code/create-forms-in-a-safe-way-to-avoid-cross-site-request-forgeries

https://symfony.com/doc/current/form/csrf_protection.html

http://en.wikipedia.org/wiki/Cross-site_request_forgery

https://docs.djangoproject.com/en/1.11/ref/csrf/

http://www.cgisecurity.com/csrf-faq.html

https://www.owasp.org/index.php/Testing_for_CSRF_(OTG-SESS-005)

https://docs.joomla.org/How_to_add_CSRF_anti-spoofing_to_forms

https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
Login Form Cross-Site Request Forgery	Login Form Cross-Site Request Forgery	Cross Site Request Forgery (CSRF) occurs when an user is tricked into clicking on a link which would automatically submit a request without the user's consent.

This can be made possible when the request does not include an anti-CSRF token, generated each time the request is visited and passed when the request is submitted, and which can be used by the web application backend to verify that the request originates from a legitimate user.

Exploiting requests vulnerable to Cross-Site Request Forgery requires different factors:

- The request must perform a sensitive action.

- The attacker must make the victim click on a link to send the request without their consent.

The exploitation of this vulnerability will in most cases have a very limited impact. However, it is possible to create complex scenarios in case the application is also vulnerable to Cross-Site Scripting.	Update the application by adding support of anti-CSRF tokens on this login form.
Most web frameworks provide either built-in solutions or have plugins that can be used to easily add these tokens to any form. Check the references for possible solutions provided for the most known frameworks.	https://codex.wordpress.org/WordPress_Nonces

https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/csrf_paper.pdf

https://www.drupal.org/docs/7/security/writing-secure-code/create-forms-in-a-safe-way-to-avoid-cross-site-request-forgeries

https://symfony.com/doc/current/form/csrf_protection.html

http://en.wikipedia.org/wiki/Cross-site_request_forgery

https://docs.djangoproject.com/en/1.11/ref/csrf/

http://www.cgisecurity.com/csrf-faq.html

https://www.owasp.org/index.php/Testing_for_CSRF_(OTG-SESS-005)

https://docs.joomla.org/How_to_add_CSRF_anti-spoofing_to_forms

https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
jQuery 1.12.4 < 3.0.0 Cross-Site Scripting	jQuery 1.12.4 < 3.0.0 Cross-Site Scripting	According to its self-reported version number, jQuery is at least 1.4.0 and prior to 1.12.0 or at least 1.12.4 and prior to 3.0.0-beta1. Therefore, it may be affected by a cross-site scripting vulnerability due to cross-domain ajax request performed without the dataType.

Note that the scanner has not tested for these issues but has instead relied only on the application's self-reported version number.	Upgrade to jQuery version 3.0.0 or later.	https://github.com/jquery/jquery/issues/2432

https://github.com/jquery/jquery/pull/2588/commits/c254d308a7d3f1eac4d0b42837804cfffcba4bb2
jQuery < 3.4.0 Prototype Pollution	jQuery < 3.4.0 Prototype Pollution	According to its self-reported version number, jQuery is prior to 3.4.0. Therefore, it may be affected by a prototype pollution vulnerability due to 'extend' function that can be tricked into modifying the prototype of 'Object'.

Note that the scanner has not tested for these issues but has instead relied only on the application's self-reported version number.	Upgrade to jQuery version 3.4.0 or later.	https://snyk.io/vuln/SNYK-JS-JQUERY-174006

https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/

https://github.com/jquery/jquery/pull/4333
jQuery 1.2.0 < 3.5.0 Cross-Site Scripting	jQuery 1.2.0 < 3.5.0 Cross-Site Scripting	According to its self-reported version number, jQuery is at least 1.2.0 and prior to 3.5.0. Therefore, it may be affected by a cross-site scripting vulnerability via the regex operation in jQuery.htmlPrefilter.

Note that the scanner has not tested for these issues but has instead relied only on the application's self-reported version number.	Upgrade to jQuery version 3.5.0 or later.	https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/

https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77
Host Header Injection	Host Header Injection	When creating URI for links in web applications, developers often resort to the HTTP Host header available in HTTP request sent by client side. A remote attacker can exploit this by sending a fake header with a domain name under his control allowing him to poison web-cache or password reset emails for example.	Web application should not trust Host and X-Forwarded-Host and should use a secure SERVER_NAME instead of these headers.	https://fr.slideshare.net/DefconRussia/http-host-header-attacks

https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html

https://www.linkedin.com/pulse/host-header-injection-depth-utkarsh-tiwari/
SSL/TLS Certificate Common Name Mismatch	SSL/TLS Certificate Common Name Mismatch	The remote server presents a SSL/TLS certificate for which the Common Name and the Subject Alternative Name don't match the server's hostname.	Purchase or generate a new SSL/TLS certificate with the right Common Name or Subject Alternative Name to replace the existing one.	
Missing 'X-Content-Type-Options' Header	Missing 'X-Content-Type-Options' Header	The HTTP 'X-Content-Type-Options' response header prevents the browser from MIME-sniffing a response away from the declared content-type.

The server did not return a correct 'X-Content-Type-Options' header, which means that this website could be at risk of a Cross-Site Scripting (XSS) attack.	Configure your web server to include an 'X-Content-Type-Options' header with a value of 'nosniff'.	https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options

https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#xcto
Missing HTTP Strict Transport Security Policy	Missing HTTP Strict Transport Security Policy	The HTTP protocol by itself is clear text, meaning that any data that is transmitted via HTTP can be captured and the contents viewed. To keep data private and prevent it from being intercepted, HTTP is often tunnelled through either Secure Sockets Layer (SSL) or Transport Layer Security (TLS). When either of these encryption standards are used, it is referred to as HTTPS.

HTTP Strict Transport Security (HSTS) is an optional response header that can be configured on the server to instruct the browser to only communicate via HTTPS. This will be enforced by the browser even if the user requests a HTTP resource on the same server.

Cyber-criminals will often attempt to compromise sensitive information passed from the client to the server using HTTP. This can be conducted via various Man-in-The-Middle (MiTM) attacks or through network packet captures.

Scanner discovered that the affected application is using HTTPS however does not use the HSTS header.	Depending on the framework being used the implementation methods will vary, however it is advised that the `Strict-Transport-Security` header be configured on the server.
One of the options for this header is `max-age`, which is a representation (in milliseconds) determining the time in which the client's browser will adhere to the header policy.
Depending on the environment and the application this time period could be from as low as minutes to as long as days.	https://tools.ietf.org/html/rfc6797

https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet

https://www.chromium.org/hsts

https://hstspreload.org/
Insecure 'Access-Control-Allow-Origin' Header	Insecure 'Access-Control-Allow-Origin' Header	Cross Origin Resource Sharing (CORS) is an HTML5 technology which gives modern web browsers the ability to bypass restrictions implemented by the Same Origin Policy.

The Same Origin Policy requires that both the JavaScript and the page are loaded from the same domain in order to allow JavaScript to interact with the page. This in turn prevents malicious JavaScript being executed when loaded from external domains.

The CORS policy allows the application to specify exceptions to the protections implemented by the browser, and enables the developer to specify allowlisted domains for which external JavaScript is permitted to execute and interact with the page.

The 'Access-Control-Allow-Origin' header is insecure when set to '*' or null, as it allows any domain to perform cross-domain requests and read responses. An attacker could abuse this configuration to retrieve private content from an application which does not use standard authentication mechanisms (for example, an Intranet allowing access from the internal network only).	Unless the target application is specifically designed to serve public content to any domain, the 'Access-Control-Allow-Origin' should be configured with an allowlist including only known and trusted domains to perform cross-domain requests if needed, or should be disabled.	https://www.owasp.org/index.php/CORS_OriginHeaderScrutiny

https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
Password Field With Auto-Complete	Password Field With Auto-Complete	In typical form-based web applications, it is common practice for developers to allow `autocomplete` within the HTML form to improve the usability of the page. With `autocomplete` enabled (default), the browser is allowed to cache previously entered form values.

For legitimate purposes, this allows the user to quickly re-enter the same data when completing the form multiple times.

When `autocomplete` is enabled on either/both the username and password fields, this could allow a cyber-criminal with access to the victim's computer the ability to have the victim's credentials automatically entered as the cyber-criminal visits the affected page.

Scanner has discovered that the affected page contains a form containing a password field that has not disabled `autocomplete`.	The `autocomplete` value can be configured in two different locations.
The first and most secure location is to disable the `autocomplete` attribute on the `<form>` HTML tag. This will disable `autocomplete` for all inputs within that form. An example of disabling `autocomplete` within the form tag is `<form autocomplete=off>`.
The second slightly less desirable option is to disable the `autocomplete` attribute for a specific `<input>` HTML tag. While this may be the less desired solution from a security perspective, it may be preferred method for usability reasons, depending on size of the form. An example of disabling the `autocomplete` attribute within a password input tag is `<input type=password autocomplete=off>`.	https://www.owasp.org/index.php/Testing_for_Vulnerable_Remember_Password_(OTG-AUTHN-005)
Permissive Content Security Policy Detected	Permissive Content Security Policy Detected	Content Security Policy (CSP) is a web security standard that helps to mitigate attacks like cross-site scripting (XSS), clickjacking or mixed content issues. CSP provides mechanisms to websites to restrict content that browsers will be allowed to load.

One or several permissive directives have been detected. See output for more details.	The following directive configurations can be applied to have a safe content security policy:

- 'frame-ancestors' should be set to 'none' to avoid rendering of page in <frame>, <iframe>, <object>, <embed>, or <applet>.
- 'form-action' should be explicitly set to 'self' to restrict form submission to the origin which the protected page is being served.
- 'upgrade-insecure-requests' and 'block-all-mixed-content' should be set to avoid mixed content (URLs served over HTTP and HTTPS) on the page.
- Any of the 'unsafe-*' directives indicate that the action is considered unsafe & it is better to refactor the code to avoid using HTML event handlers that rely on this.
- data: https: http: URI in 'default-src', 'object-src', 'base-uri' & 'script-src' allow execution of unsafe scripts and should not be set.
- * and *.* in 'script-src' and other '-src' directives allows execution of unsafe scripts and should be restricted.
- 'default-src' should be explicitly set to 'self' or 'none' and individual directives required for each source type set more permissively as required
- * and *.* in 'default-src' allows various unconfigured parameters to default to a unsafe configuration and then should not be set.
- none, unsafe-eval, unsafe-inline and self keywords require wrapping with single quotations to be valid
- 'object-src' should be explicitly set to 'none' to avoid execution of unsafe scripts.
 
If these directives are required for business continuity in your environment, apply mitigating controls suitable for your environment and work with the vendors of the products for which these directives are required.	https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

https://csp-evaluator.withgoogle.com/

https://content-security-policy.com/

https://developers.google.com/web/fundamentals/security/csp/

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
HTTP Header Information Disclosure	HTTP Header Information Disclosure	The HTTP headers sent by the remote web server disclose information that can aid an attacker, such as the server version and technologies used by the web server.	Modify the HTTP headers of the web server to not disclose detailed information about the underlying web server.	https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

http://projects.webappsec.org/w/page/13246925/Fingerprinting
Insecure Cross-Origin Resource Sharing Configuration	Insecure Cross-Origin Resource Sharing Configuration	Cross Origin Resource Sharing (CORS) is an HTML5 technology which gives modern web browsers the ability to bypass restrictions implemented by the Same Origin Policy.

The Same Origin Policy requires that both the JavaScript and the page are loaded from the same domain in order to allow JavaScript to interact with the page. This in turn prevents malicious JavaScript being executed when loaded from external domains.

The CORS policy allows the application to specify exceptions to the protections implemented by the browser, and enables the developer to specify allowlisted for which external JavaScript is permitted to execute and interact with the page.

An insecure CORS configuration allows any website to trigger requests with user credentials to the target application and read the responses, thus enabling attackers to perform privilegied actions or to retrieve potential sensitive information.	The application should be configured with an allowlist including only specific and trusted domains to perform CORS requests.	https://www.w3.org/TR/cors/#security

https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
