# Rails Security Checklist

This checklist is limited to Rails security precautions and there are many other aspects of running a Rails app that need to be secured (e.g. up-to-date operating system and other software) that this does not cover. **Consult a security expert.**

One aim for this document is to turn it into a community resource much like the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide).

**BEWARE** this checklist is not comprehensive and was originally drafted by a Rails developer with an interest in security - not a security expert - so it may have some problems - you have been warned!

## The (Work In Progress) Checklist (in no particular order)

- [ ] Notify users via email when their passwords change | HOWTOs: [Devise](https://github.com/plataformatec/devise/wiki/Notify-users-via-email-when-their-passwords-change)
- [ ] Enable secure-by-default callbacks for `ApplicationController` (and other abstract controllers)
  - [ ] Enforce authentication callbacks on actions (Devise's `authenticate_user!`)
  - [ ] Enforce authorization callbacks on actions (Pundit's `verify_authorized`)
  - [ ] Enforce authorization-related scoping callbacks on actions (Pundit's `verify_policy_scoped`)
  - [ ] Enforce CSRF protections (protect from forgery)
- [ ] When disabling security-related controller callbacks, target actions on a case-by-case basis. Be very selective and deliberate and only disable it in that concrete controller. Avoid sweeping changes in the controller class hierarchy that would make subclasses insecure-by-default.
- [ ] Perform authentication and authorization checks in `routes.rb`. It is intentional this duplicates many of the security checks you already perform in the controller callbacks (Devise's `authenticate` and `authenticated`) (motivations: defence-in-depth, swiss cheese model).
- [ ] Check all URL endpoints of engines and other Rack apps mounted in `routes.rb` are protected with correct authentication and authorization checks. For sensitive engines/Rack apps favor not leaking they are installed at all by responding with 404 to non-logged in admin users.
- [ ] Check any developer/test-related engines/Rack apps do not expose any URL endpoints in production. They should not even leak (e.g. via 500 HTTP response code) information that they are installed. Ideally don't have their gems installed in production.
- [ ] Force TLS/SSL on all URLs, including assets, images. No mixed protocols.
- [ ] Use SSL labs to check grade
- [ ] Email security (needs more info)
  - [ ] Use DKIM (https://scotthelme.co.uk/email-security-dkim/)
  - [ ] etc.
- [ ] Security scanning service (e.g. Detectify)
- [ ] Secure Headers (see gem)
- [ ] Content Security Policy
- [ ] Secure cookie flags
- [ ] Restrict cookie access as much as possible
- [ ] HSTS
- [ ] Avoid code that reads from filesystem using user-submitted file names and paths. Use a strict safelist of permitted file names and paths if this cannot be avoided.
- [ ] Favor stronger password hashing with higher workload (e.g. favor more stretches). At time of implementation, research what the currently recommended password hashing algorithms are.
- [ ] Add calendar reminder to regularly review your current password storage practices and whether to migrate to a different mechanism and/or increase the workload as CPU performance increases over time.
- [ ] Favor padding/increasing the time it takes to initially login and to report failed password attempts so as to mitigate timing attacks you may be unaware of and to mitigate brute force and user enumeration attempts. See how PayPal shows the "loading..." screen for a good few seconds when you first login (should this always be a fixed set amount of time e.g. 5 seconds and error asking user to try again if it takes longer?)(please correct me on this or add detail as this is an assumption I'm making about the reasons why PayPal do this).
- [ ] Subresource Integrity https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- [ ] Join, act on, and read code for alerts sent by [Rails Security mailing list](http://groups.google.com/group/rubyonrails-security)
- [ ] Minimize production dependencies in Gemfile. Move all non-essential production gems into their own groups (usually test and development groups)
- [ ] Brakeman (preferably Brakeman Pro) runs and results are reviewed regularly
- [ ] Update Brakeman regularly
- [ ] Run Bundler Audit regularly (and/or Snyk/Gemnasium services)
- [ ] Update Bundler Audit vulnerability database regularly
- [ ] Review `bundle outdated` results regularly and act as needed
- [ ] Avoid Rails insecure default where it operates a blocklist and logs most request parameters. A safelist would be preferable. Set up the `filter_parameters` config to log no request parameters:
```rb
# File: config/initializers/filter_parameter_logging.rb
Rails.application.config.filter_parameters += [:password]
if Rails.env.production?
  MATCH_ALL_PARAMS_PATTERN = /.+/
  Rails.application.config.filter_parameters += [MATCH_ALL_PARAMS_PATTERN]
end
```
- [ ] Test coverage for security-related code. Including but not limited to:
  - [ ] Account locking after X password attempt failures
  - [ ] Password change notifications sent
  - [ ] URL tampering (e.g. changing id values in the URL)
  - [ ] Attackers, including logged-in users, are blocked from priveleged actions and requests. For example, assume a logged-in user who is also an attacker does not need a "Delete" button to submit an HTTP request that would do the same. Attacker-crafted HTTP requests can be mimicked in request specs.
- [ ] Review and act on OWASPs literature on Ruby on Rails
- [ ] Update to always be on maintained versions of Rails. Many older Rails versions no longer receive security updates.
- [ ] Keep Ruby version up-to-date
- [ ] Check for timing attacks on password checking and token checking code
- [ ] Rack Attack to limit requests and other security concerns
- [ ] Encrypted, frequent database backups that are regularly tested can be restored. Consider keeping offline backups.
- [ ] Prevent team members from storing production data and secrets on their machines
- [ ] Enable hard disk encryption on team members hardware
- [ ] Secure staging and test environments.
  - [ ] Should not leak data. Favor not using real data in these environments. Favor scrubbing data imported from production.
  - [ ] Avoid reusing secrets that are used in the production environment.
  - [ ] Favor limiting access to staging/test environments to certain IPs and/or other extra protections (e.g. HTTP basic credentials).
  - [ ] Prevent attackers making a genuine purchase on your staging site using well-known test payment methods (e.g. Stripe test credit card numbers)
- [ ] Minimize database privileges/access on user-serving database connections. Consider user accounts, database system OS user account, isolating data by views: https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#Additional_Defenses
- [ ] Web application firewall that can detect, prevent, and alert on known SQL injection attempts
- [ ] Keep Web application firewall rules up-to-date
- [ ] Filter and validate all user input
- [ ] Regularly grep codebase for `html_safe`, `raw`, etc. usage and review
- [ ] Any routes that redirect to a URL provided in a query string or POST param should operate a safelist of acceptable redirect URLs and/or limit to only redirecting to paths within the app's URL. Do not redirect to any given URL.
- [ ] Minimize the data you store on users (especially PII) and regularly review if you can store less or delete older data. E.g. Does the app need to store a user's birthday in perpetuity (or at all) or only need it at registration to check they're old enough? Once data is no longer needed favor deleting it.
- [ ] Favor storing data encrypted (https://github.com/rocketjob/symmetric-encryption)
- [ ] Do not store API keys, tokens, secret questions/answers and other secrets in plain text. Protect via hashing and/or encryption.
- [ ] Consider encrypting stored password (and other secrets) hashes (https://blogs.dropbox.com/tech/2016/09/how-dropbox-securely-stores-your-passwords/)
- [ ] Favor multi-factor authentication
- [ ] Favor Yubikey or similar
- [ ] Nudge users towards using multi-factor authentication (provide incentives and/or enable-as-default)
- [ ] Favor limiting access per IP-address, per device, especially for administrators
- [ ] Favor sending notifications to user for significant account-related events (e.g. password change, credit card change, customer/technical support phone call made, new payment charge, new email or other contact information added, wrong password entered, 2FA disabled/enabled, other settings changes, login from a never-before used region and/or IP address)
- [ ] Consider keeping an audit trail of all significant account-related events (e.g. logins, password changes, etc. see above) that the user can review (and consider sending this as a monthly summary to them)
- [ ] Consider having multiple ways of contacting user (e.g. multiple emails) and sending important notifications through all of those channels.
- [ ] Throttle the amount of emails that can be sent to a single user (e.g. some apps allow multiple password reset emails to be sent without restriction to the same user)
- [ ] Require user confirms account (see Devise's confirmable module)
- [ ] Lock account after X failed password attempts (see Devise's lockable module)
- [ ] Timeout logins (see Devise's timeoutable module)
- [ ] Favor mitigating user enumeration (see paranoid mode in Devise and https://www.owasp.org/index.php/Testing_for_user_enumeration_(OWASP-AT-002))
- [ ] Prevent password reuse
- [ ] Enforce strong, long passwords
- [ ] Prevent commonly-used passwords (see Discourse codebase for an example)
- [ ] Proactively notify/prevent/reset users reusing passwords they've had compromised on other services (https://krebsonsecurity.com/2016/06/password-re-user-get-to-get-busy/ - interestingly Netflix apparently uses Scumblr, an open-sourced Rails app, to help with this: http://techblog.netflix.com/2014/08/announcing-scumblr-and-sketchy-search.html)
- [ ] Favor using `\A` and `\z` as regular expression anchors instead of `^` and `$` (http://guides.rubyonrails.org/security.html#regular-expressions)
- [ ] Beware any hand-written SQL snippets in the app and review for SQL injection vulnerabilities. Ensure SQL is appropriately sanitized using the ActiveRecord provided methods (e.g. see `sanitize_sql_array`).
- [ ] Avoid user-provided data being sent in emails that could be used in an attack. E.g. URLs will become links in most email clients, so if an attacker enters a URL (even into a field that is not intended to be a URL) and your app sends this to another user, that user/victim may click on the attacker-provided URL.
- [ ] Avoid allow users to upload files to your (application) servers.
- [ ] Favor scanning uploaded files for viruses/malware using a 3rd party service. don't do this on your own servers.
- [ ] Operate a safelist of allowed file uploads
- [ ] Avoid running imagemagick and other image processing software on your own infrastructure.
- [ ] Do not commit secrets to version control. Preventative measure: https://github.com/awslabs/git-secrets
- [ ] Purge version control history of any previously committed secrets.
- [ ] Consider changing any secrets that were previously committed.
- [ ] Favor changing secrets when team members leave.
- [ ] Consider DDOS protections e.g. via CloudFlare
- [ ] Provide ways for security researchers to work with you and report vulnerabilities responsibly
- [ ] Have rake task or similar ready to go for mass-password reset that will notify users of issue.
- [ ] More covered at http://guides.rubyonrails.org/security.html
- [ ] See https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet
- [ ] See http://cto-security-checklist.sqreen.io/
- [ ] Add reminders in developer calendars to do the regular tasks here and check if this checklist has changed recently.
- [ ] _etc._


## Reminders

- Security concerns trump developer inconvenience. If having a secure-by-default `ApplicationController` feels like a pain in the neck when writing a public-facing controller that requires no authentication and no authorization checks, you're doing something right.
- By default your log files and 3rd party logging services are probably receiving a lot of sensitive information they should not be. Assume log files and 3rd party logging services will expose your data sooner or later.
- Security is a moving target and is never done.
- The DRY principle is sometimes better ignored in security-related code when it prevents defence-in-depth, e.g. having authentication checks in `routes.rb` and controller callbacks is a form of duplication but provides better defence.

## Contributors

Contributions welcome!
