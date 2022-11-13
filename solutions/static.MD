# static

## Problem: 
The 'static' path page render the include of anyfile that the user asked. Coupled to the file system fail, we can include any php file in order to execute the code inside of it. More than that, we should not let the liberty of choosing any file, we should only give the possibility to give the file name

## Solution: 
Add more constraint to our uploaded files. For exemple, all our image files are uploaded in png format.