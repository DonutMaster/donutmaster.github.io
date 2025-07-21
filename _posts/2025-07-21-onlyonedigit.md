---
title: Codeforces Round 1037 (Div. 3) Problem A "Only One Digit"
date: 2025-07-21
categories: [Codeforces, Round 1037]
tags: [codeforces, coding, competitive programming]
description: Solution for coding problem "Only One Digit"
---

Link: [https://codeforces.com/contest/2126/problem/A](https://codeforces.com/contest/2126/problem/A)

> 
> Time limit per test: 1 second
> 
> Memory limit per test: 256 megabytes
{: .prompt-info }

## Problem description
You are given an integer X. You need to find the smallest non-negative integer y such that the numbers x and y share at least one common digit.

In other words, there must exist a decimal digit d that appears in both the representation of number x and number y.

## Input

The first line contains an integer t (1≤t≤1000) — the number of test cases.

The first line of each test case contains one integer x (1≤x≤1000).

## Output

For each test case, output one integer y — the minimum non-negative number that satisfies the condition.

## Example:

### Input: 
```
5
6
96
78
122
696
```

### Output:
```
6
6
7
1
6
```

## Approach
When trying to find the number y, we can see that y never has to be larger than a one digit number. Let's take the case for `75` for instance. If we choose y as `67`, x and y both share the digit `7`.

However, as you can see, if they share the digit `7` y doesn't need the digit `6`. Therefore, y will always be a one digit number.

Now, we need to choose one of the digits that appear in x that will be y. We can simply choose the smallest digit that appears in x, and that will be our answer.

## Code
```c++
#include <iostream>
using namespace std;

int main() {
    int T;
    cin >> T;
    for(int i = 0; i < T; i++) {
        string X;
        cin >> X;
        char ans = '*';
        for(int j = 0; j < X.length(); j++) {
            if(ans == '*' || X[j] < ans) {
                ans = X[j];
            }
        }
        cout << ans << '\n';
    }
    return 0;
}
```

Line 5-6: initializes T (test cases) and inputs them in

Line 7: starts a for loop for the number of test cases

Line: 8-9: initializes and inputs in X

Line: 10-15: finds the smallest existing digit inside X

Line: 16: prints out the answer

Then, the code continues this process from line 8-16 for all test cases.

## Accepted!

![Problem A Accepted](/assets/img/codeforces/round1037/problemA.png)
