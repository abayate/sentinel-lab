# How It Works (the simple version)

If you forget everything else, read this page. It explains the whole project the way
you'd explain it to a kid — and it's still accurate enough to say in an interview.

## The one-sentence version
**This project reads a computer's diary and finds the pages where a bad guy showed up.**

## The story

Imagine a **house** (a computer server). The house keeps a **diary**. Every time
*anything* happens — someone comes to the door, someone unlocks it, someone tries a
key that doesn't work — the house writes it in the diary.

Most of the diary is boring:
> "Mom came home. Dad came home. The mail arrived."

But sometimes a **burglar** shows up, and the diary writes that down too:
> "Someone tried 50 different keys on the front door in one minute."

That last line is the clue. A real person doesn't try 50 keys — a **burglar** does.

**My project is a robot that reads the whole diary and points at the burglar pages.**
It skips all the boring "Mom came home" lines and shouts when it sees the "50 keys in
one minute" line.

## The three parts (that's all there is)

1. **The diary** → the computer's *log files*. This is the evidence. Everything that
   happens gets written down here.

2. **The robot** → my program (written in Python). It reads the diary line by line and
   knows the difference between normal stuff and burglar stuff.
   - One wrong key = oops, someone mistyped. **Ignore it.**
   - 50 wrong keys fast = burglar. **Shout about it!**

3. **The wall of sticky notes** → the *dashboard* (a webpage). Every time the robot
   shouts, it puts up a sticky note: *what happened, when, and who did it.* Now a human
   can look at the wall and see all the burglars at a glance.

## The picture

```
   THE DIARY              THE ROBOT                THE WALL
 (log files)      →   (my Python program)   →   (the dashboard)
                                                                
 boring line           reads every line           puts up a note
 boring line           ignores boring ones        for each burglar
 BURGLAR LINE  ←────── catches this one ──────→   🔴 BURGLAR!
 boring line
```

## Why grown-ups (companies) care
Every real company has servers that keep these diaries, and burglars (hackers) really
do try the door all day long. Companies need robots like this to catch them. The job
of a **security engineer** is to build and improve that robot. That's exactly what this
project shows I can do.

## The grown-up words (same ideas, fancy names)
So you can "translate" when talking to professionals:

| Kid word | Grown-up word |
|----------|---------------|
| the house | a Linux server |
| the diary | log files (`/var/log/auth.log`) |
| trying 50 keys | a brute-force attack |
| the robot | the detection engine (Python) |
| "that's a burglar" rules | detection rules (YAML) |
| the official burglar names | MITRE ATT&CK techniques |
| the wall of sticky notes | the SOC dashboard |
| locking the door better afterward | hardening (CIS controls) |

That's the whole project. Everything else in this repo is just detail that supports
these three parts: **diary → robot → wall.**
