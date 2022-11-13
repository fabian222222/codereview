# Sprintf for sql query

## Problem: 
As we can see, the developper is using sprintf for sql queries. Sprintf is good function when it comes to put some variables into string but it is not in our case.
People could put some sql injection in the query and sql will execute it. For exemple, he cans get the entire database schema or data

## Solution: 
I considere that the function prepare is more efficient than sprintf. He is made to counter sql injection.