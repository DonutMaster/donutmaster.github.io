---
title: Competitive Programming Guide for Beginners
date: 2025-07-23
categories: [Competitive Programming, General]
tags: [coding, competitive programming]
description: A guide for beginners to start their competitive programming journey
---

## What is Competitive Programming?
What exactly is competitive programming? In most cases, you have several problems and usually a few hours (possibly more or less) to solve as many problems as possible or get as many points as possible.

It depends on the competition's format, time frame, number of problems, who can participate and more.

<br>

---

## IDE
An IDE (Integrated Development Environment) is how you would run your program against the test cases that are given to you (and even test cases you create yourself). Here are some recommendations from me:

#### VS Code
I use VS Code on Windows because this is an IDE that I started with from the beginning. It was a pain to set up when I first started, but afterward, it has been great to use! If you want to use it yourself (it should also have a guide on downloading a specific coding language on the left), you can follow this documentation:

- [VS Code Download Overview](https://code.visualstudio.com/docs/setup/setup-overview)

#### Geany
I would recommend Geany on Linux because of its simplicity. It is very simple to set up, and there are multiple themes available for you and more! I do not personally use Geany a lot, but it is a great tool. To download Geany, follow this GitHub link (the guide is specifically about C++, so you might have to search around for other coding languages):

- [Geany C++ Setup Overview](https://github.com/Errichto/youtube/wiki/Linux-&-Geany-Setup)

<br>

---

## Sites to Practice on
There are a few sites that I use quite frequently, and I would recommend them to everybody.

#### Codeforces
[Codeforces](https://codeforces.com) is probably the #1 competitive programming site in the world. It has millions of users and tens of thousands of contestants in each competition. It is the main platform I use to increase and practice my skills on a weekly basis.

#### Codechef
[Codechef](https://www.codechef.com/) is also a great site to participate in contests. I rarely practice from there, but I do occasionally participate in their weekly competitions.

#### Leetcode
[Leetcode](https://leetcode.com/) is another site where you can practice your DSA. A lot of the questions on Leetcode are mostly for interviews and DSA. You can participate in their weekly and biweekly contests if you are up for it.

<br>

---

## What do the problems look like?

Usually, there are six main parts: the time limit, memory limit, problem statement, input format, output format and example test cases.

#### Time Limit
Contests will not allow you to submit codes that compile (run) for too long. So, problem setters (people who create these coding problems) set a specific time limit for all codes to run in.

If your code runs for too long on their server, you will get a Time Limit Exceeded (TLE) status.

**Ex.**

![Time Limit](/assets/img/guide/timelimit.png)

<br>

#### Memory Limit
Similar to time limits, problem setters stop competitors from using too much memory. If they do, it might become too easy to solve the problems. This is the same with time limits.

If your code uses too much memory on their server, you will get a Memory Limit Exceeded (MLE) status.

**Ex.**

![Memory Limit](/assets/img/guide/memorylimit.png)

<br>

#### Problem Statement
In many problem statements, there will be a short or long story at the beginning. It will explain what you (or some character) will have to do. This part of the problems is pretty self-explanatory.

**Ex.**

![Problem Statement](/assets/img/guide/problemstatement.png)

<br>

#### Input Format
This part explains how the test cases will be formatted. Sometimes, there are multiple cases in one test case (which your code has to run inside that time and memory limit for that one test case, not for each case), or there could only be one case.

**Ex.**

![Input Format](/assets/img/guide/input.png)

<br>

#### Output Format
This is how you should print out your answer for each case, query, etc. You will have to be very careful, because you might forget something like capitalization in your code. This can lead to wrong answers and penalties.

**Ex.**

![Output Format](/assets/img/guide/output.png)

<br>

#### Example Test Cases
The problems almost always give at least one example test case with the input and correct output. You can test your code on that test case to see if your code prints out the correct output. Keep in mind that this does not necessarily mean your code will work for ALL test cases.

**Ex.**

![Example Test Cases](/assets/img/guide/exampletestcases.png)

<br>

---

## Code statuses
Code statuses are the end status of how your code ran against the test cases. Correct Answer (AC) will not be on the list because everyone knows what it is. There are five main code statuses you need to know about: Wrong Answer, Compilation Error, Runtime Error, Time Limit Exceeded and Memory Limit Exceeded

#### Wrong Answer
If your code results in a Wrong Answer (WA), it means that in some test case (possibly one of the example test cases given), the answer that your code gave is incorrect. This could mean a lot of things. You might have an incorrect solution, or your code might have a bug in it.

**Ex.**

![Wrong Answer](/assets/img/guide/WA.png)

<br>

#### Compilation Error
If your code results in a Compilation Error (CE), this means that your code is formatted incorrectly. There is a part of your code where you miswrote something.

**Ex.**

![Compilation Error](/assets/img/guide/CE.png)

<br>

#### Runtime Error
If your code results in a Runtime Error (RE), this means that your code gives an error when running your code on a test case. An example of this happening could be when you are accidentally trying to get the value of a position in an array that doesn't exist.

**Ex.**

![Runtime Error](/assets/img/guide/RE.png)

<br>

#### Time Limit Exceeded
If your code results in a Time Limit Exceeded (TLE), this means that your code took too long to compile/run. As explained above, most problems have a set time limit so that people can't brute force the answer by trying all combinations, for example.

**Ex.**

![Time Limit Exceeded](/assets/img/guide/TLE.png)

<br>

#### Memory Limit Exceeded
If your code results in a Memory Limit Exceeded (MLE), this means that your code used up too much memory while compiling/running. As explained above, most problems have a set memory limit (like time limits).

**Ex.**

![Memory Limit Exceeded](/assets/img/guide/MLE.png)

<br>

---

## Where to learn DSA
I would recommend [Errichto's YouTube Channel](https://www.youtube.com/@Errichto). He also has a video on how to start competitive programming and Codeforces. He explains a lot of important DSA topics you need as a beginner (Binary Search, DFS, etc.). [William Fiset's YouTube Channel](https://www.youtube.com/channel/UCD8yeTczadqdARzQUp29PJw) also features some data structures and algorithms.

<br>

---

## Conclusion
This is mostly what you need to know to start competitive programming! If you ever need more, always try searching on the Internet to learn what you need to know. Have fun coding!