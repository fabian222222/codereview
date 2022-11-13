# session

## Problem: 
We are checking the user with the session id which is a cookie. Futhermore, the session Id is too much simple. If we change the session ID by ourself we could have a chance to be 
connected to another account. In the session page, we can just try the session id that we want until we are admin. In that case, we will have all the user
The attacker in that situation can even use an xss attack, and retrieve the session ID. For example : alert(document.cookie) 
## Solution: 
Change the session id auto incremented by an uuid
Add a secure attribute in the cookie parameters, for example : session.cookie_secure = True in php.ini