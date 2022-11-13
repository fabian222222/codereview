# file

## Problem: 
In the path upload, the problem is that we can upload evrything that we want. Even if we have an assert but it doesn't work well. We should use a simple if statement to verify this. Furthermore, we can add any size of files that we want. It cans be very dangerous because we can crash the server with this. Also, we can upload executable files such as php files. Additionally, the code that verify the type of file is wrong, in our case, it says that the server should take all files execpt png and jpg files. I think we are looking for the opposite.

## Solution: 
We should use a simple if statement instead of assert. That is way more efficient