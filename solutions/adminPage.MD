# admin page

## Problem:

In the if statement where we are looking for admin page with "page" parameter set to "users". We can see that the developper is checking the server method, he listed three methods : get, put, post. After that, in the same statement we are checking if the user is an admin and if not, we dying the page. The problem here is that we are dumping all the users in any case at the end of the code wich means that if we are passing another method like "DELETE", we are bypassing all the if statements and we can have all users in database shown by the dumper.

## Solution:

Simple way to get this done : We can juste move the dumper in a else statement right after the admin check. So if the user is not an admin we are making the page die. And in the opposite case, we are dumping the data.
