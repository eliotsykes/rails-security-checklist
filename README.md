# Rails Security Checklist

**WORK IN PROGRESS**

BEWARE this checklist is far from comprehensive and I'm not a security expert, but a Rails developer with an interest in the security of web apps.

This chcklist is limited to Rails security precautions and there are many other aspects of running a Rails app that need to be secured (e.g. up-to-date operating system software) that this does not cover. **Consult an expert.**

I started this as a public project on a Saturday morning and may forget about it by the afternoon. My intention is to add to this when I remember its here. Lets see what happens.

## The Checklist (in no particular order)

- [ ] Notify users via email when their passwords change | HOWTOs: [Devise](https://github.com/plataformatec/devise/wiki/Notify-users-via-email-when-their-passwords-change)
- [ ] Enable secure-by-default callbacks for `ApplicationController` (and other abstract controllers)
  - [ ] Enforce authentication callbacks on actions (Devise's `authenticate_user!`)
  - [ ] Enforce authorization callbacks on actions (Pundit's `verify_authorized`)
  - [ ] Enforce authorization-related scoping callbacks on actions (Pundit's `verify_policy_scoped`)
  - [ ] Enforce CSRF protections (protect from forgery)
- [ ] When disabling security-related controller callbacks, target actions on a case-by-case basis. Be very selective and deliberate and only disable it in that concrete controller. Avoid sweeping changes in the controller class hierarchy that would make subclasses insecure-by-default.
- [ ] Perform authentication and authorization checks in `routes.rb`. It is intentional this duplicates many of the security checks you already perform in the controller callbacks (Devise's `authenticate` and `authenticated`) (motivations: defence-in-depth, swiss cheese model).
- [ ] Security scanning service (e.g. Detectify)
- [ ] Secure Headers (see gem)
- [ ] Content Security Policy
- [ ] HSTS
- [ ] Subresource Integrity https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- [ ] Join, act on, and read code for alerts sent by [Rails Security mailing list](http://groups.google.com/group/rubyonrails-security)
- [ ] Minimize production dependencies in Gemfile. Move all non-essential production gems into their own groups (usually test and development groups)
- [ ] Brakeman (preferably Brakeman Pro) runs and results are reviewed regularly
- [ ] Update Brakeman regularly
- [ ] Run Bundler Audit regularly
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
- [ ] Check for timing attacks on password checking and token checking code
- [ ] Rack Attack to limit requests and other security concerns
- [ ] Minimize database privileges/access on user-serving database connections. Consider user accounts, database system OS user account, isolating data by views: https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#Additional_Defenses
- [ ] Web application firewall that can detect, prevent, and alert on known SQL injection attempts
- [ ] Keep Web application firewall rules up-to-date
- [ ] Filter and validate all user input
- [ ] Regularly grep codebase for `html_safe`, `raw`, etc. usage and review
- [ ] Any routes that redirect to a URL provided in a query string or POST param should operate a safelist of acceptable redirect URLs and/or limit to only redirecting to paths within the app's URL. Do not redirect to any given URL.
- [ ] Favor storing data encrypted (https://github.com/rocketjob/symmetric-encryption)
- [ ] Favor 2FA
- [ ] Favor limiting access per IP-address, per device, especially for administrators
- [ ] Favor sending notifications to user for significant account-related events (e.g. password change, credit card change, customer/technical support phone call made, new payment charge, new email or other contact information added, wrong password entered, 2FA disabled/enabled, other settings changes, login from a never-before used region and/or IP address)
- [ ] Consider keeping an audit trail of all significant account-related events (e.g. logins, password changes, etc. see above) that the user can review (and consider sending this as a monthly summary to them)
- [ ] Consider having multiple ways of contacting user (e.g. multiple emails) and sending important notifications through all of those channels.
- [ ] Throttle the amount of emails that can be sent to a single user (e.g. some apps allow multiple password reset emails to be sent without restriction to the same user)
- [ ] Require user confirms account (see Devise's confirmable module)
- [ ] Lock account after X failed password attempts (see Devise's lockable module)
- [ ] Timeout logins (see Devise's timeoutable module)
- [ ] Prevent password reuse
- [ ] Enforce strong passwords
- [ ] Prevent commonly-used passwords (see Discourse codebase for an example)
- [ ] Favor using `\A` and `\z` as regular expression anchors instead of `^` and `$` (http://guides.rubyonrails.org/security.html#regular-expressions)
- [ ] Beware any hand-written SQL snippets in the app and review for SQL injection vulnerabilities. Ensure SQL is appropriately sanitized using the ActiveRecord provided methods (e.g. see `sanitize_sql_array`).
- [ ] Avoid user-provided data being sent in emails that could be used in an attack. E.g. URLs will become links in most email clients, so if an attacker enters a URL (even into a field that is not intended to be a URL) and your app sends this to another user, that user/victim may click on the attacker-provided URL.
- [ ] Avoid allow users to upload files to your (application) servers.
- [ ] Favor scanning uploaded files for viruses/malware using a 3rd party service. don't do this on your own servers.
- [ ] Operate a safelist of allowed file uploads
- [ ] Avoid running imagemagick and other image processing software on your own infrastructure.
- [ ] Do not commit secrets to version control. Preventative measure: https://github.com/awslabs/git-secrets
- [ ] Purge version control history of any previously committed secrets.
- [ ] More covered at http://guides.rubyonrails.org/security.html#regular-expressions
- [ ] See https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet
- [ ] _etc._


## Reminders

- Security concerns trump developer inconvenience. If having a secure-by-default `ApplicationController` feels like a pain in the neck when writing a public-facing controller that requires no authentication and no authorization checks, you're doing something right.
- By default your log files and 3rd party logging services are probably receiving a lot of sensitive information they should not be. Assume log files and 3rd party logging services will expose your data sooner or later.
