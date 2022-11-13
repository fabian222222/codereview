# redict

## Problem:

Do not let the user control what's inside the redirect. Even if you want to do a function for this. The execution after a redirect is an attack where the attacker ignores redirects and can then retrieve sensitive content that is from authenticated users. I consider that sha1 is too much predictible. It's also adding execute time to the code even if it's a little bit

## Solution:

You should hard write it or you can use symfony that contain bundle for those redirection. Functions like "die()" should be performed after a redirection in order to avoid any leaks.
